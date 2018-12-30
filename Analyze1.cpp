//---------------------------------------------------------------------------
#include <vcl.h>
#pragma hdrstop

#include <assert>
#include "Misc.h"

extern BYTE         *Code;
extern DWORD        TotalSize;
extern DWORD        CodeBase;
//extern  MDisasm     Disasm;
extern  DWORD       EP;
//---------------------------------------------------------------------------
//Scan proc calls
DWORD __fastcall Idr64Manager::AnalyzeProcInitial(DWORD fromAdr)
{
    BYTE        op, b1, b2;
    int         num, instrLen, instrLen1, instrLen2, _procSize;
    int         fromPos;
    int         curPos;
    DWORD       curAdr;
    DWORD       lastAdr = 0;
    DWORD       Adr, Adr1, Pos, lastMovAdr = 0;
    PInfoRec    recN;
    DISINFO     _disInfo;

    fromPos = Adr2Pos(fromAdr);
    if (fromPos < 0) return 0;
    if (IsFlagSet(cfPass0, fromPos)) return 0;
    if (IsFlagSet(cfEmbedded, fromPos)) return 0;
    if (IsFlagSet(cfExport, fromPos)) return 0;

    SetFlag(cfProcStart | cfPass0, fromPos);
    
    //Don't analyze imports
    if (IsFlagSet(cfImport, fromPos)) return 0;

    _procSize = GetProcSize(fromAdr);
    curPos = fromPos; curAdr = fromAdr;

    while (1)
    {
        if (curAdr >= CodeBase + TotalSize) break;
        //For example, cfProcEnd can be set for interface procs
        if (_procSize && curAdr - fromAdr >= _procSize) break;

        b1 = Code[curPos];
        b2 = Code[curPos + 1];
        if (!b1 && !b2 && !lastAdr) break;

        instrLen = GetDisasm().Disassemble(Code + curPos, (__int64)curAdr, &_disInfo, 0);
        //if (!instrLen) break;
        if (!instrLen)
        {
            curPos++; curAdr++;
            continue;
        }

        op = GetDisasm().GetOp(_disInfo.MnemIdx);
        //Code
        SetFlags(cfCode, curPos, instrLen);
        //Instruction begin
        SetFlag(cfInstruction, curPos);

        if (curAdr >= lastAdr) lastAdr = 0;

        //End
        if (curAdr > fromAdr && IsFlagSet(cfProcEnd, curPos))
            break;
        if (_disInfo.Ret && (!lastAdr || curAdr == lastAdr))
            break;

        if (op == OP_MOV)
            lastMovAdr = _disInfo.Offset;

        if (_disInfo.Call)  //call sub_XXXXXXXX
        {
            Adr = _disInfo.Immediate;
            if (IsValidCodeAdr(Adr))
            {
                recN = GetInfoRec(Adr);
                //If @Halt0 - end of procedure
                if (recN && recN->SameName("@Halt0"))
                {
                    if (fromAdr == EP && !lastAdr) break;
                }
                AnalyzeProcInitial(Adr);
            }
            curPos += instrLen; curAdr += instrLen;
            continue;
        }

        if (op == OP_JMP)
        {
            if (curAdr == fromAdr) return 0;
            if (_disInfo.OpType[0] == otMEM)
            {
                if (Adr2Pos(_disInfo.Offset) < 0 && (!lastAdr || curAdr == lastAdr)) return 0;
            }
            if (_disInfo.OpType[0] == otIMM)
            {
                Adr = _disInfo.Immediate;
                if (Adr2Pos(Adr) < 0 && (!lastAdr || curAdr == lastAdr)) return 0;
                if (GetSegmentNo(Adr) != 0 && GetSegmentNo(fromAdr) != GetSegmentNo(Adr) && (!lastAdr || curAdr == lastAdr)) return 0;
                if (Adr < fromAdr && (!lastAdr || curAdr == lastAdr)) return Adr;
            }
            curPos += instrLen; curAdr += instrLen;
            continue;
        }

        if (_disInfo.Conditional)
        {
            Adr = _disInfo.Immediate;
            if (IsValidCodeAdr(Adr))
            {
                if (Adr >= fromAdr && Adr > lastAdr) lastAdr = Adr;
            }
            curPos += instrLen; curAdr += instrLen;
            continue;
        }
        curPos += instrLen; curAdr += instrLen;
    }
}

//---------------------------------------------------------------------------
//Create XRefs
//Scan procedure calls (include constructors and destructors)
//Calculate size of stack for arguments
void __fastcall Idr64Manager::AnalyzeProc1(DWORD fromAdr, char xrefType, DWORD xrefAdr, int xrefOfs, bool maybeEmb)
{
	BYTE		op, b1, b2;
    bool		bpBased = false, mbemb = false;
    WORD    	bpBase = 4;
    int         num, skipNum, instrLen, instrLen1, instrLen2, procSize;
    DWORD       b;
    int         fromPos, curPos, Pos, Pos1, Pos2;
    DWORD       curAdr, Adr, Adr1, finallyAdr, endAdr, maxAdr;
    DWORD       lastMovTarget = 0, lastCmpPos = 0, lastAdr = 0;
    PInfoRec    recN, recN1;
    PXrefRec    recX;
    DISINFO     _disInfo;

    fromPos = Adr2Pos(fromAdr);
    if (fromPos < 0) return;

    recN = GetInfoRec(fromAdr);

    //Virtual constructor - don't analyze
    if (recN && recN->type.Pos("class of ") == 1) return;

    if (!recN)
    {
        recN = new InfoRec(fromPos, ikRefine);
    }
    else if (recN->kind == ikUnknown || recN->kind == ikData)
    {
        recN->kind = ikRefine;
        recN->procInfo = new InfoProcInfo;
    }

    //If xrefAdr != 0, add it to recN->xrefs
    if (xrefAdr)
    {
        recN->AddXref(xrefType, xrefAdr, xrefOfs);
        SetFlag(cfProcStart, Adr2Pos(xrefAdr));
    }

    if (maybeEmb) recN->procInfo->flags |= PF_EMBED;

    //Don't analyze imports
    if (IsFlagSet(cfImport, fromPos)) return;
    //if (IsFlagSet(cfExport, fromPos)) return;

    if (!IsFlagSet(cfPass0, fromPos))
        AnalyzeProcInitial(fromAdr);

    //If Pass1 was set skip analyze
    if (IsFlagSet(cfPass1, fromPos)) return;

    SetFlag(cfProcStart | cfPass1, fromPos);

    procSize = GetProcSize(fromAdr);
    curPos = fromPos; curAdr = fromAdr;

    while (1)
    {
        if (curAdr >= CodeBase + TotalSize) break;
        //Int64Comparison
        skipNum = ProcessInt64Comparison(curAdr, &maxAdr);
        if (skipNum > 0)
        {
            if (maxAdr > lastAdr) lastAdr = maxAdr;
            curPos += skipNum; curAdr += skipNum;
            continue;
        }
        //Int64ComparisonViaStack1
        skipNum = ProcessInt64ComparisonViaStack1(curAdr, &maxAdr);
        if (skipNum > 0)
        {
            if (maxAdr > lastAdr) lastAdr = maxAdr;
            curPos += skipNum; curAdr += skipNum;
            continue;
        }
        //Int64ComparisonViaStack2
        skipNum = ProcessInt64ComparisonViaStack2(curAdr, &maxAdr);
        if (skipNum > 0)
        {
            if (maxAdr > lastAdr) lastAdr = maxAdr;
            curPos += skipNum; curAdr += skipNum;
            continue;
        }
        b1 = Code[curPos];
        b2 = Code[curPos + 1];
        if (!b1 && !b2 && !lastAdr) break;

        instrLen = GetDisasm().Disassemble(Code + curPos, (__int64)curAdr, &_disInfo, 0);
        if (curAdr > fromAdr && IsFlagSet(cfProcEnd, curPos))
        {
            recN->procInfo->procSize = curAdr - fromAdr;
            recN->procInfo->retBytes = 0;
            //ret N
            if (_disInfo.OpNum)
            {
                recN->procInfo->retBytes = _disInfo.Immediate;//num;
            }
            break;
        }
        //if (!instrLen) break;
        if (!instrLen)
        {
            curPos++; curAdr++;
            continue;
        }
        op = GetDisasm().GetOp(_disInfo.MnemIdx);
        //Code
        SetFlags(cfCode, curPos, instrLen);
        //Instruction begin
        SetFlag(cfInstruction, curPos);

        if (curAdr >= lastAdr) lastAdr = 0;

        //Frame instructions
        if (curAdr == fromAdr &&
            _disInfo.MnemIdx == IDX_PUSH &&
            _disInfo.OpType[0] == otREG &&
            _disInfo.OpRegIdx[0] == REG_RBP)     //push rbp
        {
            SetFlag(cfFrame, curPos);
        }
        if (_disInfo.MnemIdx == IDX_MOV &&
            _disInfo.OpType[0] == otREG &&
            _disInfo.OpRegIdx[0] == REG_RBP &&
            _disInfo.OpType[1] == otREG &&
            _disInfo.OpRegIdx[1] == REG_RSP)     //mov rbp, rsp
        {
        	bpBased = true;
            recN->procInfo->flags |= PF_BPBASED;
            recN->procInfo->bpBase = bpBase;

            SetFlags(cfFrame, curPos, instrLen);
            curPos += instrLen; curAdr += instrLen;
            continue;
        }
        if (_disInfo.MnemIdx == IDX_MOV &&
            _disInfo.OpType[0] == otREG &&
            _disInfo.OpRegIdx[0] == REG_RSP &&
            _disInfo.OpType[1] == otREG &&
            _disInfo.OpRegIdx[1] == REG_RBP)     //mov rsp, rbp
        {
            SetFlags(cfFrame, curPos, instrLen);
            curPos += instrLen; curAdr += instrLen;
            continue;
        }
        if (op == OP_JMP)
        {
            if (curAdr == fromAdr) break;
            if (_disInfo.OpType[0] == otMEM)
            {
                if (Adr2Pos(_disInfo.Offset) < 0 && (!lastAdr || curAdr == lastAdr)) break;
            }
            if (_disInfo.OpType[0] == otIMM)
            {
                Adr = _disInfo.Immediate; Pos = Adr2Pos(Adr);
                if (Pos < 0 && (!lastAdr || curAdr == lastAdr)) break;
                if (GetSegmentNo(Adr) != 0 && GetSegmentNo(fromAdr) != GetSegmentNo(Adr) && (!lastAdr || curAdr == lastAdr)) break;
                SetFlag(cfLoc, Pos);
                recN1 = GetInfoRec(Adr);
                if (!recN1) recN1 = new InfoRec(Pos, ikUnknown);
                recN1->AddXref('J', fromAdr, curAdr - fromAdr);

                if (Adr < fromAdr && (!lastAdr || curAdr == lastAdr)) break;
            }
        }

        //End of procedure
        if (_disInfo.Ret)
        {
            if (!lastAdr || curAdr == lastAdr)
            {
                //Proc end
                SetFlag(cfProcEnd, curPos + instrLen);
                recN->procInfo->procSize = curAdr - fromAdr + instrLen;
                recN->procInfo->retBytes = 0;
                //ret N
                if (_disInfo.OpNum)
                {
                    recN->procInfo->retBytes = _disInfo.Immediate;//num;
                }
                break;
            }
        }
        //push
        if (op == OP_PUSH)
        {
            SetFlag(cfPush, curPos);
            bpBase += 8;
        }
        //pop
        if (op == OP_POP)  SetFlag(cfPop, curPos);
        //add (sub) rsp,...
        if (_disInfo.OpType[0] == otREG &&
            _disInfo.OpRegIdx[0] == REG_RSP &&
            _disInfo.OpType[1] == otIMM)
        {
            if (op == OP_ADD) bpBase -= (int)_disInfo.Immediate;
            if (op == OP_SUB) bpBase += (int)_disInfo.Immediate;
            //skip
            SetFlags(cfSkip, curPos, instrLen);
            curPos += instrLen; curAdr += instrLen;
            continue;
        }
        ////fstp [esp]
        //if (Disasm.GetOp(_disInfo.MnemIdx) == IDX_FSTP && _disInfo.BaseReg == REG_RSP) SetFlag(cfFush, curPos);

        //skip
        if (GetDisasm().GetOp(_disInfo.MnemIdx) == IDX_SAHF || GetDisasm().GetOp(_disInfo.MnemIdx) == IDX_WAIT)
        {
            SetFlags(cfSkip, curPos, instrLen);
            curPos += instrLen; curAdr += instrLen;
            continue;
        }

        if (op == OP_MOV) lastMovTarget = _disInfo.Offset;
        if (op == OP_CMP) lastCmpPos = curPos;

        //mov rcx,rbp - embedded procedure (next instruction is not "neg rcx")
        if (_disInfo.MnemIdx == IDX_MOV &&
            _disInfo.OpType[0] == otREG &&
            _disInfo.OpRegIdx[0] == REG_RCX &&
            _disInfo.OpType[1] == otREG &&
            _disInfo.OpRegIdx[1] == REG_RBP)
        {
            curPos += instrLen; curAdr += instrLen;
            instrLen1 = GetDisasm().Disassemble(Code + curPos, (__int64)curAdr, &_disInfo, 0);
            if (_disInfo.MnemIdx == IDX_NEG &&
                _disInfo.OpType[0] == otREG &&
                _disInfo.OpRegIdx[0] == REG_RCX)
            {
                curPos += instrLen1; curAdr += instrLen1;
                continue;
            }
            mbemb = true;
            continue;
        }

        if (_disInfo.Call)
        {
            SetFlag(cfCall, curPos);
            Adr = _disInfo.Immediate;
            if (IsValidCodeAdr(Adr) && Adr2Pos(Adr) >= 0)
            {
                SetFlag(cfLoc, Adr2Pos(Adr));
                AnalyzeProc1(Adr, 'C', fromAdr, curAdr - fromAdr, mbemb);
                mbemb = false;

                recN1 = GetInfoRec(Adr);
                if (recN1 && recN1->procInfo)
                {
                    if (recN1->HasName())
                    {
                        if (recN1->SameName("@Halt0"))
                        {
                            SetFlags(cfSkip, curPos, instrLen);
                            if (fromAdr == EP && !lastAdr)
                            {
                                SetFlag(cfProcEnd, curPos + instrLen);
                                recN->procInfo->procSize = curAdr - fromAdr + instrLen;
                                recN->SetName("EntryPoint");
                                recN->procInfo->retBytes = 0;
                                break;
                            }
                        }

                        int begPos, endPos;
                        //If called procedure is @ClassCreate, then current procedure is constructor
                        if (recN1->SameName("@ClassCreate"))
                        {
                            recN->kind = ikConstructor;
                            //Code from instruction cmp... until this call is not sufficient (mark skipped)
                            begPos = GetNearestUpInstruction1(curPos, fromPos, "cmp");
                            if (begPos != -1) SetFlags(cfSkip, begPos, curPos + instrLen - begPos);
                        }
                        else if (recN1->SameName("@AfterConstruction"))
                        {
                            begPos = GetNearestUpInstruction2(curPos, fromPos, "test", "cmp");
                            endPos = GetNearestDownInstruction(curPos, "jmp");
                            //Code from instruction cmp... until address XXX (of jmp XXX) is not sufficient (mark skipped)
                            GetDisasm().Disassemble(Code + endPos, (__int64)Pos2Adr(endPos), &_disInfo, 0);
                            endPos = Adr2Pos(_disInfo.Immediate);
                            if (begPos != -1 && endPos != -1) SetFlags(cfSkip, begPos, endPos - begPos);
                        }
                        else if (recN1->SameName("@BeforeDestruction"))
                            SetFlag(cfSkip, curPos);
                        //If called procedure is @ClassDestroy, then current procedure is destructor
                        else if (recN1->SameName("@ClassDestroy"))
                        {
                            recN->kind = ikDestructor;
                            begPos = GetNearestUpInstruction2(curPos, fromPos, "test", "cmp");
                            if (begPos != -1) SetFlags(cfSkip, begPos, curPos + instrLen - begPos);
                        }
                    }
                }
            }
            curPos += instrLen; curAdr += instrLen;
            continue;
        }

        if (_disInfo.Branch && instrLen == 2)    //Short relative abs jmp or cond jmp
        {
            Adr = _disInfo.Immediate;
            if (IsValidCodeAdr(Adr))
            {
                Pos = Adr2Pos(Adr);
                if (!IsFlagSet(cfEmbedded, Pos))//Possible branch to start of Embedded proc (for ex. in proc TextToFloat))
                {
                    SetFlag(cfLoc, Pos);
                    //Mark possible start of Loop
                    if (Adr < curAdr)
                        SetFlag(cfLoop, Pos);
                    recN1 = GetInfoRec(Adr);
                    if (!recN1) recN1 = new InfoRec(Pos, ikUnknown);
                    recN1->AddXref('C', fromAdr, curAdr - fromAdr);
                    if (Adr >= fromAdr && Adr > lastAdr) lastAdr = Adr;
                }
            }
            curPos += instrLen; curAdr += instrLen;
            continue;
        }
        if (_disInfo.Branch && instrLen == 5)    //Relative abs jmp or cond jmp
        {
            Adr = _disInfo.Immediate;
            if (IsValidCodeAdr(Adr))
            {
                Pos = Adr2Pos(Adr);
                SetFlag(cfLoc, Pos);
                //Mark possible start of Loop
                if (Adr < curAdr)
                    SetFlag(cfLoop, Pos);
                recN1 = GetInfoRec(Adr);
                if (!recN1 && Adr >= fromAdr && Adr > lastAdr) lastAdr = Adr;
            }
            curPos += instrLen; curAdr += instrLen;
            continue;
        }
        //Second operand - immediate and is valid address
        if (_disInfo.OpType[1] == otIMM)
        {
            Pos = Adr2Pos(_disInfo.Immediate);
            //Immediate must be valid code address outside current procedure
            if (Pos >= 0 && IsValidCodeAdr(_disInfo.Immediate) && (_disInfo.Immediate < fromAdr || _disInfo.Immediate >= fromAdr + procSize))
            {
                //Position must be free
                if (IsFlagEmpty(Pos))
                {
                    //No Name
                    if (!HasInfosAt(Pos))
                    {
                        //Address must be outside current procedure
                        if (_disInfo.Immediate < fromAdr || _disInfo.Immediate >= fromAdr + procSize)
                        {
                            //If valid code lets user decide later
                            int codeValidity = IsValidCode(_disInfo.Immediate);

                            if (codeValidity == 1)  //Code
                                AnalyzeProc1(_disInfo.Immediate, 'D', fromAdr, curAdr - fromAdr, false);
                        }
                    }
                }
                //If slot is not free (procedure is already loaded)
                else if (IsFlagSet(cfProcStart, Pos))
                    AnalyzeProc1(_disInfo.Immediate, 'D', fromAdr, curAdr - fromAdr, false);
            }
            curPos += instrLen; curAdr += instrLen;
            continue;
        }
        curPos += instrLen; curAdr += instrLen;
    }
}
//---------------------------------------------------------------------------

