//---------------------------------------------------------------------------
#include <vcl.h>
#pragma hdrstop

#include <assert>
#include "KnowledgeBase.h"
#include "Misc.h"
#include "TypeInfo.h"

extern BYTE         *Code;
extern DWORD        TotalSize;
extern DWORD        CodeBase;
//extern MDisasm      Disasm;
extern DWORD        EP;
//extern int          VmtSelfPtr;
extern int          dummy;
extern String       SourceFile;
extern int          LastResStrNo;
//---------------------------------------------------------------------------
//Registers Indexes (IDR32)
//0    1    2    3    4    5    6    7
//al,  cl,  dl,  bl,  ah,  ch,  dh,  bh
//8    9    10   11   12   13   14   15
//ax,  cx,  dx,  bx,  sp,  bp,  si,  di
//16   17   18   19   20   21   22   23
//eax, ecx, edx, ebx, esp, ebp, esi, edi
//24   25   26   27   28   29   30   31
//es,  cs,  ss,  ds,  fs,  gs

#define RCONTEXT_REGNUM 130
//0    1    2    3    4    5    6    7    8    9    10    11    12    13    14    15
//eax, ecx, edx, ebx, esp, ebp, esi, edi, r8d, r9d, r10d, r11d, r12d, r13d, r14d, r15d
//16   17   18   19   20   21   22   23   24  25  26   27   28   29   30   31
//rax, rcx, rdx, rbx, rsp, rbp, rsi, rdi, r8, r9, r10, r11, r12, r13, r14, r15
//32  33  34  35  36  37  38  39  40   41   42    43    44    45    46    47
//ax, cx, dx, bx, sp, bp, si, di, r8w, r9w, r10w, r11w, r12w, r13w, r14w, r15w
//48  49  50  51  52   53   54   55   56   57   58    59    60    61    62    63
//al, cl, dl, bl, spl, bpl, sil, dil, r8b, r9b, r10b, r11b, r12b, r13b, r14b, r15b
//64  65  66  67
//ah, ch, dh, bh
//74  75  76  77  78  79
//es, cs, ss, ds, fs, gs
//80 81 82  83  84  85  86  87  88  89
//      st0 st1 st2 st3 st4 st5 st6 st7
//90  91  92  93  94  95  96  97
//mm0 mm1 mm2 mm3 mm4 mm5 mm6 mm7
//98   99   100  101  102  103  104  105  106  107  108   109   110   111   112   113
//xmm0 xmm1 xmm2 xmm3 xmm4 xmm5 xmm6 xmm7 xmm8 xmm9 xmm10 xmm11 xmm12 xmm13 xmm14 xmm15
//114  115  116  117  118  119  120  121  122  123  124   125   126   127   128   129
//ymm0 ymm1 ymm2 ymm3 ymm4 ymm5 ymm6 ymm7 ymm8 ymm9 ymm10 ymm11 ymm12 ymm13 ymm14 ymm15
//structure for saving context of all registers (branch instruction)
typedef struct
{
    int     sp;
    DWORD   adr;
    RINFO   registers[RCONTEXT_REGNUM];
} RCONTEXT, *PRCONTEXT;
//---------------------------------------------------------------------------
PRCONTEXT __fastcall GetCtx(TList* Ctx, DWORD Adr)
{
    for (int n = 0; n < Ctx->Count; n++)
    {
        PRCONTEXT rinfo = (PRCONTEXT)Ctx->Items[n];
        if (rinfo->adr == Adr) return rinfo;
    }
    return 0;
}
//---------------------------------------------------------------------------
void __fastcall SetRegisterValue(PRINFO regs, int Idx, DWORD Value)
{
    for (int n = 0; n < RCONTEXT_REGNUM; n++)
    {
        if (GetDisasm().IsSimilarRegs(Idx, n))
        {
            regs[n].value = Value;
        }
    }
}
//---------------------------------------------------------------------------
//Possible values
//'V' - Virtual table base (for calls processing)
//'v' - var
//'L' - lea local var
//'l' - local var
//'A' - lea argument
//'a' - argument
//'I' - Integer
void __fastcall SetRegisterSource(PRINFO regs, int Idx, char Value)
{
    for (int n = 0; n < RCONTEXT_REGNUM; n++)
    {
        if (GetDisasm().IsSimilarRegs(Idx, n))
        {
            regs[n].source = Value;
        }
    }
}
//---------------------------------------------------------------------------
void __fastcall SetRegisterType(PRINFO regs, int Idx, String Value)
{
    for (int n = 0; n < RCONTEXT_REGNUM; n++)
    {
        if (GetDisasm().IsSimilarRegs(Idx, n))
        {
            regs[n].type = Value;
        }
    }
}
//---------------------------------------------------------------------------
void __fastcall Idr64Manager::AnalyzeProc2(DWORD fromAdr, bool addArg, bool AnalyzeRetType)
{
    //saved context
    TList *sctx = new TList;
    for (int n = 0; n < 3; n++)
    {
        if (!AnalyzeProc2(fromAdr, addArg, AnalyzeRetType, sctx)) break;
    }
    //delete sctx
    CleanupList<RCONTEXT>(sctx);
}
//---------------------------------------------------------------------------
bool __fastcall Idr64Manager::AnalyzeProc2(DWORD fromAdr, bool addArg, bool AnalyzeRetType, TList *sctx)
{
	BYTE		    op, b1, b2;
    char            source;
	bool		    reset, bpBased, vmt, fContinue = false;
    WORD            bpBase;
    int             n, num, instrLen, instrLen1, instrLen2, _ap, _procSize;
    int             reg1Idx, reg2Idx;
    int			    sp = -1;
    int             fromPos, curPos, Pos;
    DWORD           curAdr;
    DWORD           lastMovAdr = 0;
    DWORD           procAdr, Val, Adr, Adr1;
    DWORD           reg, varAdr, classAdr, vmtAdr, lastAdr = 0;
    PInfoRec        recN, recN1;
    PLOCALINFO      locInfo;
    PARGINFO        argInfo;
    PFIELDINFO 	    fInfo = 0;
    PRCONTEXT       rinfo;
    RINFO     	    rtmp;
    String		    comment, typeName, className = "", varName, varType;
    String          _rcx_Type, _rdx_Type, _r8_Type, _r9_Type, sType;
    RINFO     	    registers[RCONTEXT_REGNUM];
    RINFO   	    stack[256];
    DISINFO         DisInfo, DisInfo1;

    fromPos = Adr2Pos(fromAdr);
    if (fromPos < 0) return false;
    if (IsFlagSet(cfPass2, fromPos)) return false;
    if (IsFlagSet(cfEmbedded, fromPos)) return false;
    if (IsFlagSet(cfExport, fromPos)) return false;

    //Import - return ret type of function
    if (IsFlagSet(cfImport, fromPos)) return false;
    recN = GetInfoRec(fromAdr);

    //if recN = 0 (Interface Methods!!!) then return
    if (!recN || !recN->procInfo) return false;

    //Procedure from Knowledge Base not analyzed
    if (recN && recN->kbIdx != -1) return false;

    //if (!IsFlagSet(cfPass1, fromPos))
    //???

    SetFlag(cfProcStart | cfPass2, fromPos);

    //If function name contains class name get it
    className = ExtractClassName(recN->GetName());
    bpBased = (recN->procInfo->flags & PF_BPBASED);
    bpBase = (recN->procInfo->bpBase);

    rtmp.result = 0; rtmp.source = 0; rtmp.value = 0; rtmp.type = "";
    for (n = 0; n < RCONTEXT_REGNUM; n++) registers[n] = rtmp;

    //Get args
    _rcx_Type = _rdx_Type = _r8_Type = _r9_Type = "";
    BYTE callKind = recN->procInfo->flags & 7;
    if (recN->procInfo->args && !callKind)  //fastcall
    {
    	for (n = 0; n < recN->procInfo->args->Count; n++)
        {
        	PARGINFO argInfo = (PARGINFO)recN->procInfo->args->Items[n];
            if (argInfo->Ndx == 0)
            {
            	if (className != "")
                	registers[REG_RCX].type = className;
                else
            		registers[REG_RCX].type = argInfo->TypeDef;
                _rcx_Type = registers[REG_RCX].type;
                //var
                if (argInfo->Tag == 0x22) registers[REG_RCX].source = 'v';
                continue;
            }
            if (argInfo->Ndx == 1)
            {
            	registers[REG_RDX].type = argInfo->TypeDef;
                _rdx_Type = registers[REG_RDX].type;
                //var
                if (argInfo->Tag == 0x22) registers[REG_RDX].source = 'v';
                continue;
            }
            if (argInfo->Ndx == 2)
            {
           		registers[REG_R8].type = argInfo->TypeDef;
                _r8_Type = registers[REG_R8].type;
                //var
                if (argInfo->Tag == 0x22) registers[REG_R8].source = 'v';
                continue;
            }
            if (argInfo->Ndx == 3)
            {
           		registers[REG_R9].type = argInfo->TypeDef;
                _r9_Type = registers[REG_R9].type;
                //var
                if (argInfo->Tag == 0x22) registers[REG_R9].source = 'v';
                continue;
            }
          	break;
        }
    }
    else if (className != "")
    {
    	registers[REG_RCX].type = className;
    }

    _procSize = GetProcSize(fromAdr);
    curPos = fromPos; curAdr = fromAdr;

    while (1)
    {
//!!!
//if (curAdr == 0x)
//n = n;
        if (curAdr >= CodeBase + TotalSize) break;

        b1 = Code[curPos];
        b2 = Code[curPos + 1];
        if (!b1 && !b2 && !lastAdr) break;

        instrLen = GetDisasm().Disassemble(Code + curPos, (__int64)curAdr, &DisInfo, 0);
        //if (!instrLen) break;
        if (!instrLen)
        {
            curPos++; curAdr++;
            continue;
        }

        op = GetDisasm().GetOp(DisInfo.MnemIdx);
        //Code
        SetFlags(cfCode, curPos, instrLen);
        //Instruction begin
        SetFlag(cfInstruction, curPos);

        if (curAdr >= lastAdr) lastAdr = 0;

        if (op == OP_JMP)
        {
            if (curAdr == fromAdr) break;
            if (DisInfo.OpType[0] == otMEM)
            {
                if (Adr2Pos(DisInfo.Offset) < 0 && (!lastAdr || curAdr == lastAdr)) break;
            }
            if (DisInfo.OpType[0] == otIMM)
            {
                Adr = DisInfo.Immediate;
                if (Adr2Pos(Adr) < 0 && (!lastAdr || curAdr == lastAdr)) break;
                if (GetSegmentNo(Adr) != 0 && GetSegmentNo(fromAdr) != GetSegmentNo(Adr) && (!lastAdr || curAdr == lastAdr)) break;
                if (Adr < fromAdr && (!lastAdr || curAdr == lastAdr)) break;
                curPos += instrLen; curAdr += instrLen;
                continue;
            }
        }

        if (DisInfo.Ret)
        {
            //End of proc
            if (!lastAdr || curAdr == lastAdr)
            {
                if (AnalyzeRetType)
                {
                    //If rax type is not empty then find nearest up instruction of its assignment
                    if (registers[REG_RAX].type != "")
                    {
                        for (Pos = curPos - 1; Pos >= fromPos; Pos--)
                        {
                            if (IsFlagSet(cfInstruction, Pos) && !IsFlagSet(cfSkip, Pos))
                            {
                                GetDisasm().Disassemble(Code + Pos, (__int64)Pos2Adr(Pos), &DisInfo, 0);
                                //If branch - break
                                if (DisInfo.Branch) break;
                                //If call
                                //Other cases (call [reg+Ofs]; call [Adr]) need to add
                                if (DisInfo.Call)
                                {
                                    Adr = DisInfo.Immediate;
                                    if (IsValidCodeAdr(Adr))
                                    {
                                        recN1 = GetInfoRec(Adr);
                                        if (recN1 && recN1->procInfo/*recN1->kind == ikFunc*/)
                                        {
                                            typeName = recN1->type;
                                            recN1 = GetInfoRec(fromAdr);
                                            if (!(recN1->procInfo->flags & (PF_EVENT | PF_DYNAMIC)) &&
                                                recN1->kind != ikConstructor && recN1->kind != ikDestructor)
                                            {
                                                recN1->kind = ikFunc;
                                                recN1->type = typeName;
                                            }
                                        }
                                    }
                                }
                                else if (IsFlagSet(cfSetC, Pos))
                                {
                                    recN1 = GetInfoRec(fromAdr);
                                    if (!(recN1->procInfo->flags & (PF_EVENT | PF_DYNAMIC)) &&
                                        recN1->kind != ikConstructor && recN1->kind != ikDestructor)
                                    {
                                        recN1->kind = ikFunc;
                                        recN1->type = registers[REG_RCX].type;
                                    }
                                }
                            }
                        }
                    }
                }
                break;
            }
            if (!IsFlagSet(cfSkip, curPos)) sp = -1;
        }

        //cfBracket
        if (IsFlagSet(cfBracket, curPos))
        {
        	if (op == OP_PUSH && sp < 255)
            {
                reg1Idx = DisInfo.OpRegIdx[0];
                sp++;
                stack[sp] = registers[reg1Idx];
            }
            else if (op == OP_POP && sp >= 0)
            {
                reg1Idx = DisInfo.OpRegIdx[0];
                registers[reg1Idx] = stack[sp];
                sp--;
            }
            curPos += instrLen; curAdr += instrLen;
            continue;
        }
        //Проверим, не попал ли внутрь инструкции Fixup или ThreadVar
        bool    NameInside = false;
        for (int k = 1; k < instrLen; k++)
        {
            if (HasInfosAt(curPos + k))
            {
                NameInside = true;
                break;
            }
        }

        reset = ((op & OP_RESET) != 0);

        if (op == OP_MOV) lastMovAdr = DisInfo.Offset;

        //If loc then try get context
        if (curAdr != fromAdr && IsFlagSet(cfLoc, curPos))
        {
            rinfo = GetCtx(sctx, curAdr);
            if (rinfo)
            {
                sp = rinfo->sp;
                for (n = 0; n < RCONTEXT_REGNUM; n++) registers[n] = rinfo->registers[n];
            }
            //context not found - set flag to continue on the next step
            else
            {
                fContinue = true;
            }
        }
        //branch
        if (DisInfo.Branch)
        {
            Adr = DisInfo.Immediate;
            if (IsValidCodeAdr(Adr))
            {
                _ap = Adr2Pos(Adr);
                //SetFlag(cfLoc, _ap);
                //recN1 = GetInfoRec(Adr);
                //if (!recN1) recN1 = new InfoRec(_ap, ikUnknown);
                //recN1->AddXref('C', fromAdr, curAdr - fromAdr);
                //Save context
                if (!GetCtx(sctx, Adr))
                {
                    rinfo = new RCONTEXT;
                    rinfo->sp = sp;
                    rinfo->adr = Adr;
                    for (n = 0; n < RCONTEXT_REGNUM; n++) rinfo->registers[n] = registers[n];
                    sctx->Add((void*)rinfo);
                }
                if (Adr >= fromAdr && Adr > lastAdr) lastAdr = Adr;
            }
            curPos += instrLen; curAdr += instrLen;
            continue;
        }
        if (registers[REG_RAX].type != "" && registers[REG_RAX].type[1] == '#') //??? Need to search!!!
        {
            DWORD dd = *((DWORD*)(registers[REG_RAX].type.c_str()));
            //After call @GetTls look at next instruction with operand [eax+N]
            if (dd == 'SLT#')
            {
                //If not internal name (Fixup, ThreadVar)
                if (!NameInside)
                {
                    //Destination (GlobalLists := TList.Create)
                    //Source (GlobalLists.Add)
                    if ((DisInfo.OpType[0] == otMEM || DisInfo.OpType[1] == otMEM) && DisInfo.BaseReg == REG_RAX)
                    {
                        _ap = Adr2Pos(curAdr); assert(_ap >= 0);
                        recN1 = GetInfoRec(curAdr + 1);
                        if (!recN1) recN1 = new InfoRec(_ap + 1, ikThreadVar);
                        if (!recN1->HasName()) recN1->SetName(String("threadvar_") + DisInfo.Offset);
                    }
                }
                SetRegisterValue(registers, REG_RAX, 0xFFFFFFFF);
                registers[REG_RAX].type = "";
                curPos += instrLen; curAdr += instrLen;
                continue;
            }
        }
        //Call
        if (DisInfo.Call)
        {
            Adr = DisInfo.Immediate;
            if (IsValidImageAdr(Adr))
            {
            	recN = GetInfoRec(Adr);
                if (recN && recN->procInfo)
                {
                    int retBytes = (int)recN->procInfo->retBytes;
                    if (retBytes != -1 && sp >= retBytes)
                        sp -= retBytes;
                    else
                        sp = -1;

					//For constructors type is in rcx
                    if (recN->kind == ikConstructor)
                    {
                        //If dl = 1, then rcx after call used
                        if (registers[REG_DL].value == 1)
                        {
                            classAdr = GetClassAdr(registers[REG_RCX].type);
                            if (IsValidImageAdr(classAdr))
                            {
                                //Add xref to vmt info
                                recN1 = GetInfoRec(classAdr);
                                recN1->AddXref('D', Adr, 0);

                                comment = registers[REG_RCX].type + ".Create";
                                AddPicode(curPos, OP_CALL, comment, 0);
                                AnalyzeCall(fromAdr, curPos, Adr, registers);
                            }
                        }
                        SetFlag(cfSetC, curPos);
                    }
                    else
                    {
                        //Found @Halt0 - exit
                        if (recN->SameName("@Halt0") && fromAdr == EP && !lastAdr) break;

                    	DWORD dynAdr;
                        if (recN->SameName("@ClassCreate"))
                        {
                             SetRegisterType(registers, REG_RCX, className);
                             SetFlag(cfSetC, curPos);
                        }
                        else if (recN->SameName("@CallDynaInst") ||
                                 recN->SameName("@CallDynaClass"))
                        {
                            comment = GetDynaInfo(GetClassAdr(registers[REG_RCX].type), registers[REG_SI].value, &dynAdr);	//si
                            AddPicode(curPos, OP_CALL, comment, dynAdr);
                        	SetRegisterType(registers, REG_RCX, "");
                        }
                        else if (recN->SameName("@FindDynaInst") ||
                                 recN->SameName("@FindDynaClass"))
                        {
                            comment = GetDynaInfo(GetClassAdr(registers[REG_RCX].type), registers[REG_DX].value, &dynAdr);	//dx
                            AddPicode(curPos, OP_CALL, comment, dynAdr);
                            SetRegisterType(registers, REG_RAX, "");
                        }
                        //@XStrArrayClr
                        else if (recN->SameName("@LStrArrayClr") || recN->SameName("@WStrArrayClr") || recN->SameName("@UStrArrayClr"))
                        {
                            DWORD arrAdr = registers[REG_RCX].value;
                            int cnt = registers[REG_EDX].value;
                            //Direct address???
                            if (IsValidImageAdr(arrAdr))
                            {
                            }
                            //Local vars
                            else if ((registers[REG_RCX].source & 0xDF) == 'L')
                            {
                                recN1 = GetInfoRec(fromAdr);
                                int aofs = registers[REG_RCX].value;
                                for (int aa = 0; aa < cnt; aa++, aofs += 8)
                                {
                                    if (recN->SameName("@LStrArrayClr"))
                                        recN1->procInfo->AddLocal(aofs, 8, "", "AnsiString");
                                    else if (recN->SameName("@WStrArrayClr"))
                                        recN1->procInfo->AddLocal(aofs, 8, "", "WideString");
                                    else if (recN->SameName("@UStrArrayClr"))
                                        recN1->procInfo->AddLocal(aofs, 8, "", "UString");
                                }
                            }
                            SetRegisterType(registers, REG_RAX, "");
                        }
                        else
                        {
                            String retType = AnalyzeCall(fromAdr, curPos, Adr, registers);
                            recN1 = GetInfoRec(fromAdr);
                            for (int mm = 0; mm < RCONTEXT_REGNUM; mm++)
                            {
                                if (mm != REG_RCX && mm != REG_RDX && mm != REG_R8 && mm != REG_R9) continue;
                                if (registers[mm].result == 1)
                                {
                                    if ((registers[mm].source & 0xDF) == 'L')
                                    {
                                        recN1->procInfo->AddLocal((int)registers[mm].value, 4, "", registers[mm].type);
                                    }
                                    else if ((registers[mm].source & 0xDF) == 'A')
                                        recN1->procInfo->AddArg(0x21, (int)registers[mm].value, 4, "", registers[mm].type);
                                }
                            }
                            SetRegisterType(registers, REG_RAX, retType);
                        }
                    }
                }
                else
                {
                    sp = -1;
            		SetRegisterType(registers, REG_RAX, "");
                }
            }
            //call Memory
            else if (DisInfo.OpType[0] == otMEM && DisInfo.IndxReg == -1)
            {
                sp = -1;
                //call [Offset]
                if (DisInfo.BaseReg == -1)
                {
                }
                //call [BaseReg + Offset]
                else
                {
                    classAdr = registers[DisInfo.BaseReg].value;
                    SetRegisterType(registers, REG_RAX, "");
                    if (IsValidCodeAdr(classAdr) && registers[DisInfo.BaseReg].source == 'V')
                    {
                        recN = GetInfoRec(classAdr);
                        if (recN && recN->vmtInfo && recN->vmtInfo->methods)
                        {
                            for (int mm = 0; mm < recN->vmtInfo->methods->Count; mm++)
                            {
                                PMethodRec recM = (PMethodRec)recN->vmtInfo->methods->Items[mm];
                                if (recM->kind == 'V' && recM->id == (int)DisInfo.Offset)
                                {
                                    recN1 = GetInfoRec(recM->address);

                                    if (recM->name != "")
                                        comment = recM->name;
                                    else
                                    {
                                        if (recN1->HasName())
                                            comment = recN1->GetName();
                                        else
                                            comment = GetClsName(classAdr) + ".sub_" + Val2Str8(recM->address);
                                    }
                                    AddPicode(curPos, OP_CALL, comment, recM->address);

                                    recN1->AddXref('V', fromAdr, curAdr - fromAdr);
                                    if (recN1->kind == ikFunc) SetRegisterType(registers, REG_RAX, recN1->type);
                                    break;
                                }
                            }
                        }
                        registers[DisInfo.BaseReg].source = 0;
                    }
                    else
                    {
                    	int callOfs = DisInfo.Offset;
                    	typeName = TrimTypeName(registers[DisInfo.BaseReg].type);
                        if (typeName != "" && callOfs > 0)
                        {
                        	Pos = GetNearestUpInstruction(curPos, fromPos, 1); Adr = Pos2Adr(Pos);
                            instrLen1 = GetDisasm().Disassemble(Code + Pos, (__int64)Adr, &DisInfo, 0);
                            if (DisInfo.Offset == callOfs + 4)
                            {
                                fInfo = GetField(typeName, callOfs, &vmt, &vmtAdr);
                                if (fInfo)
                                {
                                    if (fInfo->Name != "") AddPicode(curPos, OP_CALL, typeName + "." + fInfo->Name, 0);
                                    if (vmt)
                                        AddFieldXref(fInfo, fromAdr, curAdr - fromAdr, 'C');
                                    else
                                        delete fInfo;
                                }
                                else if (vmt)
                                {
                                    fInfo = AddField(fromAdr, curAdr - fromAdr, typeName, FIELD_PUBLIC, callOfs, -1, "", "");
                                    if (fInfo) AddFieldXref(fInfo, fromAdr, curAdr - fromAdr, 'C');
                                }
                            }
                        }
                    }
                }
            }
            SetRegisterSource(registers, REG_RCX, 0);
            SetRegisterSource(registers, REG_RDX, 0);
            SetRegisterSource(registers, REG_R8, 0);
            SetRegisterSource(registers, REG_R9, 0);
            SetRegisterValue(registers, REG_RAX, -1);
            curPos += instrLen; curAdr += instrLen;
            continue;
        }
        sType = String(DisInfo.sSize);
        //floating point operations
        if (DisInfo.Float)
        {
            float       singleVal;
            long double extendedVal;
            String		fVal = "";

            switch (DisInfo.OpSize)
            {
            case 4:
                sType = "Single";
                break;
            //Double or Comp???
            case 8:
            	sType = "Double";
                break;
            case 10:
                sType = "Extended";
                break;
            default:
            	sType = "Float";
                break;
            }

        	Adr = DisInfo.Offset;
            _ap = Adr2Pos(Adr);
        	//fxxx [Adr]
        	if (DisInfo.BaseReg == -1 && DisInfo.IndxReg == -1)
            {
                if (IsValidImageAdr(Adr))
                {
                    if (_ap >= 0)
                    {
                        switch (DisInfo.OpSize)
                        {
                        case 4:
                            singleVal = 0; memmove((void*)&singleVal, Code + _ap, 4);
                            fVal = FloatToStr(singleVal);
                            break;
                        //Double or Comp???
                        case 8:
                            break;
                        case 10:
                            try
                            {
                                extendedVal = 0; memmove((void*)&extendedVal, Code + _ap, 10);
                                fVal = FloatToStr(extendedVal);
                            }
                            catch (Exception &E)
                            {
                                fVal = "Impossible!";
                            }
                            break;
                        }
                        SetFlags(cfData, _ap, DisInfo.OpSize);

                        recN = GetInfoRec(Adr);
                        if (!recN) recN = new InfoRec(_ap, ikData);
                        if (!recN->HasName()) recN->SetName(fVal);
                        if (recN->type == "") recN->type = sType;
                        if (!IsValidCodeAdr(Adr)) recN->AddXref('D', fromAdr, curAdr - fromAdr);
                    }
                    else
                    {
                        recN = AddToBSSInfos(Adr, MakeGvarName(Adr), sType);
                        if (recN) recN->AddXref('C', fromAdr, curAdr - fromAdr);
                    }
                }
            }
            else if (DisInfo.BaseReg != -1)
            {
            	//fxxxx [BaseReg + Offset]
            	if (DisInfo.IndxReg == -1)
                {
                    //fxxxx [rbp - Offset]
                    if (bpBased && DisInfo.BaseReg == REG_RBP && (int)DisInfo.Offset < 0)
                    {
                        recN1 = GetInfoRec(fromAdr);
                        recN1->procInfo->AddLocal((int)DisInfo.Offset, DisInfo.OpSize, "", sType);
                    }
                    //fxxx [rsp + Offset]
                    else if (DisInfo.BaseReg == REG_RSP)
                    {
                        dummy = 1;
                    }
                    else
                    {
                        //fxxxx [BaseReg]
                        if (!DisInfo.Offset)
                        {
                            varAdr = registers[DisInfo.BaseReg].value;
                            if (IsValidImageAdr(varAdr))
                            {
                                _ap = Adr2Pos(varAdr);
                                if (_ap >= 0)
                                {
                                    recN1 = GetInfoRec(varAdr);
                                    if (!recN1) recN1 = new InfoRec(_ap, ikData);
                                    MakeGvar(recN1, varAdr, curAdr);
                                    recN1->type = sType;
                                    if (!IsValidCodeAdr(varAdr)) recN1->AddXref('D', fromAdr, curAdr - fromAdr);
                                }
                                else
                                {
                                    recN1 = AddToBSSInfos(varAdr, MakeGvarName(varAdr), sType);
                                    if (recN1) recN1->AddXref('C', fromAdr, curAdr - fromAdr);
                                }
                            }
                        }
                        //fxxxx [BaseReg + Offset]
                        else if ((int)DisInfo.Offset > 0)
                        {
                            typeName = TrimTypeName(registers[DisInfo.BaseReg].type);
                            if (typeName != "")
                            {
                                fInfo = GetField(typeName, (int)DisInfo.Offset, &vmt, &vmtAdr);
                                if (fInfo)
                                {
                                    if (vmt)
                                    {
                                        if (CanReplace(fInfo->Type, sType)) fInfo->Type = sType;
                                        AddFieldXref(fInfo, fromAdr, curAdr - fromAdr, 'C');
                                    }
                                    else
                                    {
                                        delete fInfo;
                                    }
                                    //if (vmtAdr) typeName = GetClsName(vmtAdr);
                                    AddPicode(curPos, 0, typeName, DisInfo.Offset);
                                }
                                else if (vmt)
                                {
                                    fInfo = AddField(fromAdr, curAdr - fromAdr, typeName, FIELD_PUBLIC, (int)DisInfo.Offset, -1, "", sType);
                                    if (fInfo)
                                    {
                                        AddFieldXref(fInfo, fromAdr, curAdr - fromAdr, 'C');
                                    	AddPicode(curPos, 0, typeName, DisInfo.Offset);
                                    }
                                }
                            }
                        }
                        //fxxxx [BaseReg - Offset]
                        else
                        {
                        }
                    }
                }
                //fxxxx [BaseReg + IndxReg*Scale + Offset]
                else
                {
                }
            }
            curPos += instrLen; curAdr += instrLen;
            continue;
        }
        //No operands
        if (DisInfo.OpNum == 0)
        {
        	//cdq
            if (op == OP_CDQ)
            {
                SetRegisterSource(registers, REG_RAX, 'I');
            	SetRegisterValue(registers, REG_RAX, -1);
                SetRegisterType(registers, REG_RAX, "Integer");
                SetRegisterSource(registers, REG_RDX, 'I');
                SetRegisterValue(registers, REG_RDX, -1);
                SetRegisterType(registers, REG_RDX, "Integer");
            }
        }
        //1 operand
        else if (DisInfo.OpNum == 1)
        {
        	//op Imm
            if (DisInfo.OpType[0] == otIMM)
            {
            	if (IsValidImageAdr(DisInfo.Immediate))
                {
                    _ap = Adr2Pos(DisInfo.Immediate);
                    if (_ap >= 0)
                    {
                        recN1 = GetInfoRec(DisInfo.Immediate);
                        if (recN1) recN1->AddXref('C', fromAdr, curAdr - fromAdr);
                    }
                    else
                    {
                        recN1 = AddToBSSInfos(DisInfo.Immediate, MakeGvarName(DisInfo.Immediate), "");
                        if (recN1) recN1->AddXref('C', fromAdr, curAdr - fromAdr);
                    }
                }
            }
            //op reg
            else if (DisInfo.OpType[0] == otREG && op != OP_UNK && op != OP_PUSH)
            {
                reg1Idx = DisInfo.OpRegIdx[0];
                SetRegisterSource(registers, reg1Idx, 0);
                SetRegisterValue(registers, reg1Idx, -1);
                SetRegisterType(registers, reg1Idx, "");
            }
            //op [BaseReg + Offset]
            else if (DisInfo.OpType[0] == otMEM)
            {
                if (DisInfo.BaseReg != -1 && DisInfo.IndxReg == -1 && (int)DisInfo.Offset > 0)
                {
                    typeName = TrimTypeName(registers[DisInfo.BaseReg].type);
                    if (typeName != "")
                    {
                        fInfo = GetField(typeName, (int)DisInfo.Offset, &vmt, &vmtAdr);
                        if (fInfo)
                        {
                            if (vmt)
                                AddFieldXref(fInfo, fromAdr, curAdr - fromAdr, 'C');
                            else
                                delete fInfo;
                            AddPicode(curPos, 0, typeName, DisInfo.Offset);
                        }
                        else if (vmt)
                        {
                            fInfo = AddField(fromAdr, curAdr - fromAdr, typeName, FIELD_PUBLIC, (int)DisInfo.Offset, -1, "", sType);
                            if (fInfo)
                            {
                                AddFieldXref(fInfo, fromAdr, curAdr - fromAdr, 'C');
                            	AddPicode(curPos, 0, typeName, DisInfo.Offset);
                            }
                        }
                    }
                }
            	if (op == OP_IMUL || op == OP_IDIV)
                {
                    SetRegisterSource(registers, REG_RAX, 0);
                    SetRegisterValue(registers, REG_RAX, -1);
                    SetRegisterType(registers, REG_RAX, "Integer");
                    SetRegisterSource(registers, REG_RDX, 0);
                    SetRegisterValue(registers, REG_RDX, -1);
                    SetRegisterType(registers, REG_RDX, "Integer");
                }
            }
        }
        //2 or 3 operands
        else if (DisInfo.OpNum >= 2)
        {
            if (op & OP_A2)
            {
                if (DisInfo.OpType[0] == otREG)	//cop reg,...
                {
                    reg1Idx = DisInfo.OpRegIdx[0];
                    source = registers[reg1Idx].source;
                    SetRegisterSource(registers, reg1Idx, 0);

                    if (DisInfo.OpType[1] == otIMM)	//cop reg, Imm
                    {
                    	if (reset)
                        {
                            typeName = TrimTypeName(registers[reg1Idx].type);
                            SetRegisterValue(registers, reg1Idx, -1);
                            SetRegisterType(registers, reg1Idx, "");

                            if (op == OP_ADD)
                            {
                            	if (typeName != "" && source != 'v')
                                {
                                    fInfo = GetField(typeName, (int)DisInfo.Immediate, &vmt, &vmtAdr);
                                    if (fInfo)
                                    {
                                        registers[reg1Idx].type = fInfo->Type;
                                        if (vmt)
                                            AddFieldXref(fInfo, fromAdr, curAdr - fromAdr, 'C');
                                        else
                                            delete fInfo;
                                        //if (vmtAdr) typeName = GetClsName(vmtAdr);
                                        AddPicode(curPos, 0, typeName, DisInfo.Immediate);
                                    }
                                    else if (vmt)
                                    {
                                        fInfo = AddField(fromAdr, curAdr - fromAdr, typeName, FIELD_PUBLIC, (int)DisInfo.Immediate, -1, "", "");
                                        if (fInfo)
                                        {
                                            AddFieldXref(fInfo, fromAdr, curAdr - fromAdr, 'C');
                                        	AddPicode(curPos, 0, typeName, DisInfo.Immediate);
                                        }
                                    }
                                }
                            }
                            else
                            {
                            	if (op == OP_MOV) SetRegisterValue(registers, reg1Idx, DisInfo.Immediate);
                                SetRegisterSource(registers, reg1Idx, 'I');
                                if (IsValidImageAdr(DisInfo.Immediate))
                                {
                                    _ap = Adr2Pos(DisInfo.Immediate);
                                    if (_ap >= 0)
                                    {
                                        recN1 = GetInfoRec(DisInfo.Immediate);
                                        if (recN1)
                                        {
                                            SetRegisterType(registers, reg1Idx, recN1->type);
                                            bool _addXref = false;
                                            switch (recN1->kind)
                                            {
                                            case ikString:
                                                SetRegisterType(registers, reg1Idx, "ShortString");
                                                _addXref = true;
                                                break;
                                            case ikLString:
                                                SetRegisterType(registers, reg1Idx, "AnsiString");
                                                _addXref = true;
                                                break;
                                            case ikWString:
                                                SetRegisterType(registers, reg1Idx, "WideString");
                                                _addXref = true;
                                                break;
                                            case ikCString:
                                                SetRegisterType(registers, reg1Idx, "PAnsiChar");
                                                _addXref = true;
                                                break;
                                            case ikWCString:
                                                SetRegisterType(registers, reg1Idx, "PWideChar");
                                                _addXref = true;
                                                break;
                                            case ikUString:
                                                SetRegisterType(registers, reg1Idx, "UString");
                                                _addXref = true;
                                                break;
                                            }
                                            if (_addXref) recN1->AddXref('C', fromAdr, curAdr - fromAdr);
                                        }
                                    }
                                    else
                                    {
                                        recN1 = AddToBSSInfos(DisInfo.Immediate, MakeGvarName(DisInfo.Immediate), "");
                                        if (recN1) recN1->AddXref('C', fromAdr, curAdr - fromAdr);
                                    }
                                }
                            }
                        }
                    }
                    else if (DisInfo.OpType[1] == otREG)	//cop reg, reg
                    {
                        reg2Idx = DisInfo.OpRegIdx[1];
                    	if (reset)
                        {
                            if (op == OP_MOV)
                            {
                            	SetRegisterSource(registers, reg1Idx, registers[reg2Idx].source);
                                SetRegisterValue(registers, reg1Idx, registers[reg2Idx].value);
                                SetRegisterType(registers, reg1Idx, registers[reg2Idx].type);
                            }
                            else if (op == OP_XOR)
                            {
                                SetRegisterValue(registers, reg1Idx, registers[reg1Idx].value ^ registers[reg2Idx].value);
                                SetRegisterType(registers, reg1Idx, "");
                            }
                            else if (op == OP_XCHG)
                            {
                                rtmp = registers[reg1Idx]; registers[reg1Idx] = registers[reg2Idx]; registers[reg2Idx] = rtmp;
                            }
                            else if (op == OP_IMUL || op == OP_IDIV)
                            {
                            	SetRegisterSource(registers, reg1Idx, 0);
                                SetRegisterValue(registers, reg1Idx, -1);
                                SetRegisterType(registers, reg1Idx, "Integer");
                                if (reg1Idx != reg2Idx)
                                {
                                	SetRegisterSource(registers, reg2Idx, 0);
                                	SetRegisterValue(registers, reg2Idx, -1);
                                	SetRegisterType(registers, reg2Idx, "Integer");
                            	}
                            }
                            else
                            {
                                SetRegisterValue(registers, reg1Idx, -1);
                                SetRegisterType(registers, reg1Idx, "");
                            }
                        }
                    }
                    else if (DisInfo.OpType[1] == otMEM)	//cop reg, Memory
                    {
                    	if (DisInfo.BaseReg == -1)
                        {
                        	if (DisInfo.IndxReg == -1)	//cop reg, [Offset]
                            {
                            	if (reset)
                                {
                                    if (op == OP_IMUL)
                                    {
                                        SetRegisterSource(registers, reg1Idx, 0);
                                        SetRegisterValue(registers, reg1Idx, -1);
                                        SetRegisterType(registers, reg1Idx, "Integer");
                                    }
                                    else
                                    {
                                        SetRegisterValue(registers, reg1Idx, -1);
                                        SetRegisterType(registers, reg1Idx, "");
                                    }
                                }
                                Adr = DisInfo.Offset;
                                if (IsValidImageAdr(Adr))
                                {
                                    _ap = Adr2Pos(Adr);
                                    if (_ap >= 0)
                                    {
                                        recN = GetInfoRec(Adr);
                                        if (recN)
                                        {
                                            MakeGvar(recN, Adr, curAdr);
                                            if (recN->kind == ikVMT)
                                            {
                                                if (reset)
                                                {
                                                    SetRegisterType(registers, reg1Idx, recN->GetName());
                                                    SetRegisterValue(registers, reg1Idx, Adr - Vmt.SelfPtr);
                                                }
                                            }
                                            else
                                            {
                                                if (reset) registers[reg1Idx].type = recN->type;
                                                if (reg1Idx <= REG_R15)
                                                {
                                                    if (reg1Idx >= REG_RAX)
                                                    {
                                                        if (IsFlagSet(cfImport, _ap))
                                                        {
                                                            recN1 = GetInfoRec(Adr);
                                                            AddPicode(curPos, OP_COMMENT, recN1->GetName(), 0);
                                                        }
                                                        else if (!IsFlagSet(cfRTTI, _ap))
                                                        {
                                                            Val = *((DWORD*)(Code + _ap));
                                                            if (reset) SetRegisterValue(registers, reg1Idx, Val);
                                                            if (IsValidImageAdr(Val))
                                                            {
                                                                _ap = Adr2Pos(Val);
                                                                if (_ap >= 0)
                                                                {
                                                                    recN1 = GetInfoRec(Val);
                                                                    if (recN1)
                                                                    {
                                                                        MakeGvar(recN1, Val, curAdr);
                                                                        varName = recN1->GetName();
                                                                        if (varName != "") recN->SetName("^" + varName);
                                                                        if (recN->type != "") registers[reg1Idx].type = recN->type;
                                                                        varType = recN1->type;
                                                                        if (varType != "")
                                                                        {
                                                                            recN->type = varType;
                                                                            registers[reg1Idx].type = varType;
                                                                        }
                                                                    }
                                                                    else
                                                                    {
                                                                        recN1 = new InfoRec(_ap, ikData);
                                                                        MakeGvar(recN1, Val, curAdr);
                                                                        varName = recN1->GetName();
                                                                        if (varName != "") recN->SetName("^" + varName);
                                                                        if (recN->type != "") registers[reg1Idx].type = recN->type;
                                                                    }
                                                                    if (recN) recN->AddXref('C', fromAdr, curAdr - fromAdr);
                                                                }
                                                                else
                                                                {
                                                                    if (recN->HasName())
                                                                        recN1 = AddToBSSInfos(Val, recN->GetName(), recN->type);
                                                                    else
                                                                        recN1 = AddToBSSInfos(Val, MakeGvarName(Val), recN->type);
                                                                    if (recN1) recN1->AddXref('C', fromAdr, curAdr - fromAdr);
                                                                }
                                                            }
                                                            else
                                                            {
                                                                AddPicode(curPos, OP_COMMENT, "0x" + Val2Str0(Val), 0);
                                                                SetFlags(cfData, _ap, 4);
                                                            }
                                                        }
                                                    }
                                                    else
                                                    {
                                                        if (reg1Idx <= REG_R15B)
                                                        {
                                                            Val = *(Code + _ap);
                                                        }
                                                        else if (reg1Idx <= REG_R15W)
                                                        {
                                                            Val = *((WORD*)(Code + _ap));
                                                        }
                                                        AddPicode(curPos, OP_COMMENT, "0x" + Val2Str0(Val), 0);
                                                        SetFlags(cfData, _ap, 4);
                                                    }
                                                }
                                            }
                                        }
                                        else
                                        {
                                            recN = new InfoRec(_ap, ikData);
                                            MakeGvar(recN, Adr, curAdr);
                                            if (reg1Idx <= REG_R15)
                                            {
                                                if (reg1Idx >= REG_RAX)
                                                {
                                                    Val = *((DWORD*)(Code + _ap));
                                                    if (reset) SetRegisterValue(registers, reg1Idx, Val);
                                                    if (IsValidImageAdr(Val))
                                                    {
                                                        _ap = Adr2Pos(Val);
                                                        if (_ap >= 0)
                                                        {
                                                            recN->kind = ikPointer;
                                                            recN1 = GetInfoRec(Val);
                                                            if (recN1)
                                                            {
                                                                MakeGvar(recN1, Val, curAdr);
                                                                varName = recN1->GetName();
                                                                if (varName != "" && (recN1->kind == ikLString || recN1->kind == ikWString || recN1->kind == ikUString))
                                                                    varName = "\"" + varName + "\"";
                                                                if (varName != "") recN->SetName("^" + varName);
                                                                if (recN->type != "") registers[reg1Idx].type = recN->type;
                                                                varType = recN1->type;
                                                                if (varType != "")
                                                                {
                                                                    recN->type = varType;
                                                                    registers[reg1Idx].type = varType;
                                                                }
                                                            }
                                                            else
                                                            {
                                                                recN1 = new InfoRec(_ap, ikData);
                                                                MakeGvar(recN1, Val, curAdr);
                                                                varName = recN1->GetName();
                                                                if (varName != "" && (recN1->kind == ikLString || recN1->kind == ikWString || recN1->kind == ikUString))
                                                                    varName = "\"" + varName + "\"";
                                                                if (varName != "") recN->SetName("^" + varName);
                                                                if (recN->type != "") registers[reg1Idx].type = recN->type;
                                                            }
                                                            if (recN1) recN1->AddXref('C', fromAdr, curAdr - fromAdr);
                                                        }
                                                        else
                                                        {
                                                            recN1 = AddToBSSInfos(Val, MakeGvarName(Val), "");
                                                            if (recN1)
                                                            {
                                                                recN1->AddXref('C', fromAdr, curAdr - fromAdr);
                                                                if (recN->type != "") recN->type = recN1->type;
                                                            }
                                                        }
                                                    }
                                                    else
                                                    {
                                                        AddPicode(curPos, OP_COMMENT, "0x" + Val2Str0(Val), 0);
                                                        SetFlags(cfData, _ap, 4);
                                                    }
                                                }
                                                else
                                                {
                                                    if (reg1Idx <= REG_R15B)
                                                    {
                                                        Val = *(Code + _ap);
                                                    }
                                                    else if (reg1Idx <= REG_R15W)
                                                    {
                                                        Val = *((WORD*)(Code + _ap));
                                                    }
                                                    AddPicode(curPos, OP_COMMENT, "0x" + Val2Str0(Val), 0);
                                                    SetFlags(cfData, _ap, 4);
                                                }
                                            }
                                        }
                                    }
                                    else
                                    {
                                        recN1 = AddToBSSInfos(Adr, MakeGvarName(Adr), "");
                                        if (recN1) recN1->AddXref('C', fromAdr, curAdr - fromAdr);
                                    }

                                }
                            }
                            else	//cop reg, [Offset + IndxReg*Scale]
                            {
                            	if (reset)
                                {
                                    if (op == OP_IMUL)
                                    {
                                        SetRegisterSource(registers, reg1Idx, 0);
                                        SetRegisterValue(registers, reg1Idx, -1);
                                        SetRegisterType(registers, reg1Idx, "Integer");
                                    }
                                    else
                                    {
                                        SetRegisterValue(registers, reg1Idx, -1);
                                        SetRegisterType(registers, reg1Idx, "");
                                    }
                                }

                                Adr = DisInfo.Offset;
                                if (IsValidImageAdr(Adr))
                                {
                                    _ap = Adr2Pos(Adr);
                                    if (_ap >= 0)
                                    {
                                        recN = GetInfoRec(Adr);
                                        if (recN)
                                        {
                                            if (recN->kind == ikVMT)
                                                typeName = recN->GetName();
                                            else
                                                typeName = recN->type;

                                            if (reset) SetRegisterType(registers, reg1Idx, typeName);
                                            if (!IsValidCodeAdr(Adr)) recN->AddXref('C', fromAdr, curAdr - fromAdr);
                                        }
                                    }
                                    else
                                    {
                                        recN1 = AddToBSSInfos(Adr, MakeGvarName(Adr), "");
                                        if (recN1) recN1->AddXref('C', fromAdr, curAdr - fromAdr);
                                    }
                                }
                            }
                        }
                        else
                        {
                        	if (DisInfo.IndxReg == -1)
                            {
                            	if (bpBased && DisInfo.BaseReg == REG_RBP)	//cop reg, [rbp + Offset]
                                {
                                    if ((int)DisInfo.Offset < 0)	//cop reg, [rbp - Offset]
                                    {
                                        if (reset)
                                        {
                                            if (op == OP_IMUL)
                                            {
                                                SetRegisterSource(registers, reg1Idx, 0);
                                                SetRegisterValue(registers, reg1Idx, -1);
                                                SetRegisterType(registers, reg1Idx, "Integer");
                                            }
                                            else
                                            {
                                                SetRegisterSource(registers, reg1Idx, (op == OP_LEA) ? 'L' : 'l');
                                                SetRegisterValue(registers, reg1Idx, DisInfo.Offset);
                                                SetRegisterType(registers, reg1Idx, "");
                                            }
                                        }
                                        //xchg rcx, [rbp-8] (rcx = 0, [ebp-8] = _rcx_)//???!!!
                                        if ((int)DisInfo.Offset == -8 && reg1Idx == REG_RCX)
                                        {
                                            recN1 = GetInfoRec(fromAdr);
                                            locInfo = recN1->procInfo->AddLocal((int)DisInfo.Offset, 8, "", "");
                                            SetRegisterType(registers, reg1Idx, _rcx_Type);
                                        }
                                        else
                                        {
                                            recN1 = GetInfoRec(fromAdr);
                                            locInfo = recN1->procInfo->AddLocal((int)DisInfo.Offset, DisInfo.OpSize, "", "");
                                            //mov, xchg
                                            if (op == OP_MOV || op == OP_XCHG)
                                            {
                                                SetRegisterType(registers, reg1Idx, locInfo->TypeDef);
                                            }
                                            else if (op == OP_LEA && locInfo->TypeDef != "")
                                            {
                                            	SetRegisterType(registers, reg1Idx, locInfo->TypeDef);
                                            }
                                        }
                                    }
                                    else	//cop reg, [ebp + Offset]
                                    {
                                        if (reset)
                                        {
                                            if (op == OP_IMUL)
                                            {
                                                SetRegisterSource(registers, reg1Idx, 0);
                                                SetRegisterValue(registers, reg1Idx, -1);
                                                SetRegisterType(registers, reg1Idx, "Integer");
                                            }
                                            else
                                            {
                                                SetRegisterValue(registers, reg1Idx, -1);
                                                SetRegisterValue(registers, reg1Idx, -1);
                                                SetRegisterType(registers, reg1Idx, "");
                                            }
                                        }
                                        if (bpBased && addArg)
                                        {
                                            recN1 = GetInfoRec(fromAdr);
                                            argInfo = recN1->procInfo->AddArg(0x21, DisInfo.Offset, 4, "", "");
                                            if (op == OP_MOV || op == OP_LEA || op == OP_XCHG)
                                            {
                                                SetRegisterSource(registers, reg1Idx, (op == OP_LEA) ? 'A' : 'a');
                                                SetRegisterValue(registers, reg1Idx, DisInfo.Offset);
                                                SetRegisterType(registers, reg1Idx, argInfo->TypeDef);
                                            }
                                        }
                                    }
                                }
                                else if (DisInfo.BaseReg == REG_RSP)	//cop reg, [rsp + Offset]
                                {
                                    if (reset)
                                    {
                                    	if (op == OP_IMUL)
                                        {
                                        	SetRegisterSource(registers, reg1Idx, 0);
                                            SetRegisterValue(registers, reg1Idx, -1);
                                            SetRegisterType(registers, reg1Idx, "Integer");
                                        }
                                        else
                                        {
                                        	SetRegisterValue(registers, reg1Idx, -1);
                                        	SetRegisterType(registers, reg1Idx, "");
                                        }
                                    }
                                }
                                else	//cop reg, [BaseReg + Offset]
                                {
                                    if (!DisInfo.Offset)	//cop reg, [BaseReg]
                                    {
                                        Adr = registers[DisInfo.BaseReg].value;
                                        typeName = TrimTypeName(registers[DisInfo.BaseReg].type);
                                        if (reset)
                                        {
                                            if (op == OP_IMUL)
                                            {
                                                SetRegisterSource(registers, reg1Idx, 0);
                                                SetRegisterValue(registers, reg1Idx, -1);
                                                SetRegisterType(registers, reg1Idx, "Integer");
                                            }
                                            else
                                            {
                                            	SetRegisterValue(registers, reg1Idx, -1);
                                            	SetRegisterType(registers, reg1Idx, "");
                                            }
                                            
                                            if (typeName != "")
                                            {
                                            	if (typeName[1] == '^') typeName = typeName.SubString(2, typeName.Length() - 1);
                                               	SetRegisterValue(registers, reg1Idx, GetClassAdr(typeName));
                                                SetRegisterType(registers, reg1Idx, typeName); //???
                                               	SetRegisterSource(registers, reg1Idx, 'V');	//Virtual table base (for calls processing)
                                            }
                                            if (IsValidImageAdr(Adr))
                                            {
                                                _ap = Adr2Pos(Adr);
                                                if (_ap >= 0)
                                                {
                                                    recN = GetInfoRec(Adr);
                                                    if (recN)
                                                    {
                                                        if (recN->kind == ikVMT)
                                                        {
                                                            SetRegisterType(registers, reg1Idx, recN->GetName());
                                                            SetRegisterValue(registers, reg1Idx, Adr - Vmt.SelfPtr);
                                                        }
                                                        else
                                                        {
                                                            SetRegisterType(registers, reg1Idx, recN->type);
                                                            if (recN->type != "")
                                                                SetRegisterValue(registers, reg1Idx, GetClassAdr(recN->type));
                                                        }
                                                    }
                                                }
                                                else
                                                {
                                                    AddToBSSInfos(Adr, MakeGvarName(Adr), "");
                                                }
                                            }
                                        }
                                    }
                                    else if ((int)DisInfo.Offset > 0)	//cop reg, [BaseReg + Offset]
                                    {
                                        typeName = TrimTypeName(registers[DisInfo.BaseReg].type);
                                        if (reset)
                                        {
                                            if (op == OP_IMUL)
                                            {
                                                SetRegisterSource(registers, reg1Idx, 0);
                                                SetRegisterValue(registers, reg1Idx, -1);
                                                SetRegisterType(registers, reg1Idx, "Integer"); sType = "Integer";
                                            }
                                            else
                                            {
                                        		SetRegisterValue(registers, reg1Idx, -1);
                                            	SetRegisterType(registers, reg1Idx, "");
                                            }
                                        }
                                        if (typeName != "")
                                        {
                                            fInfo = GetField(typeName, (int)DisInfo.Offset, &vmt, &vmtAdr);
                                            if (fInfo)
                                            {
                                                if (op == OP_MOV || op == OP_XCHG)
                                                {
                                                    registers[reg1Idx].type = fInfo->Type;
                                                }
                                                if (CanReplace(fInfo->Type, sType)) fInfo->Type = sType;

                                                if (vmt)
                                                    AddFieldXref(fInfo, fromAdr, curAdr - fromAdr, 'C');
                                                else
                                                    delete fInfo;
                                                //if (vmtAdr) typeName = GetClsName(vmtAdr);
                                                AddPicode(curPos, 0, typeName, DisInfo.Offset);
                                            }
                                            else if (vmt)
                                            {
                                                fInfo = AddField(fromAdr, curAdr - fromAdr, typeName, FIELD_PUBLIC, (int)DisInfo.Offset, -1, "", sType);
                                                if (fInfo)
                                                {
                                                    AddFieldXref(fInfo, fromAdr, curAdr - fromAdr, 'C');
                                                	AddPicode(curPos, 0, typeName, DisInfo.Offset);
                                                }
                                            }
                                        }
                                    }
                                    else	//cop reg, [BaseReg - Offset]
                                    {
                                    	if (reset)
                                        {
                                            if (op == OP_IMUL)
                                            {
                                                SetRegisterSource(registers, reg1Idx, 0);
                                                SetRegisterValue(registers, reg1Idx, -1);
                                                SetRegisterType(registers, reg1Idx, "Integer");
                                            }
                                            else
                                            {
                                        		SetRegisterValue(registers, reg1Idx, -1);
                                        		SetRegisterType(registers, reg1Idx, "");
                                            }
                                        }
                                    }
                                }
                            }
                            else	//cop reg, [BaseReg + IndxReg*Scale + Offset]
                            {
                            	if (DisInfo.BaseReg == REG_RBP)	//cop reg, [rbp + IndxReg*Scale + Offset]
                                {
                                    if (reset)
                                    {
                                        if (op == OP_IMUL)
                                        {
                                            SetRegisterSource(registers, reg1Idx, 0);
                                            SetRegisterValue(registers, reg1Idx, -1);
                                            SetRegisterType(registers, reg1Idx, "Integer");
                                        }
                                        else
                                        {
                                        	SetRegisterValue(registers, reg1Idx, -1);
                                        	SetRegisterType(registers, reg1Idx, "");
                                        }
                                    }
                                }
                                else if (DisInfo.BaseReg == REG_RSP)	//cop reg, [rsp + IndxReg*Scale + Offset]
                                {
                                    if (reset)
                                    {
                                        if (op == OP_IMUL)
                                        {
                                            SetRegisterSource(registers, reg1Idx, 0);
                                            SetRegisterValue(registers, reg1Idx, -1);
                                            SetRegisterType(registers, reg1Idx, "Integer");
                                        }
                                        else
                                        {
                                        	SetRegisterValue(registers, reg1Idx, -1);
                                        	SetRegisterType(registers, reg1Idx, "");
                                        }
                                    }
                                }
                                else	//cop reg, [BaseReg + IndxReg*Scale + Offset]
                                {
                                	typeName = TrimTypeName(registers[DisInfo.BaseReg].type);
                                	if (reset)
                                    {
                                    	if (op == OP_LEA)
                                        {
                                        	//BaseReg - points to class
                                            if (typeName != "")
                                            {
                                                SetRegisterSource(registers, reg1Idx, 0);
                                                SetRegisterValue(registers, reg1Idx, -1);
                                                SetRegisterType(registers, reg1Idx, "");
                                            }
                                            //Else - general arifmetics
                                            else
                                            {
                                                SetRegisterSource(registers, reg1Idx, 0);
                                                SetRegisterValue(registers, reg1Idx, -1);
                                                SetRegisterType(registers, reg1Idx, "Integer");
                                            }
                                        }
                                        else if (op == OP_IMUL)
                                        {
                                            SetRegisterSource(registers, reg1Idx, 0);
                                            SetRegisterValue(registers, reg1Idx, -1);
                                            SetRegisterType(registers, reg1Idx, "Integer");
                                        }
                                        else
                                        {
                                        	SetRegisterValue(registers, reg1Idx, -1);
                                        	SetRegisterType(registers, reg1Idx, "");
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                //cop Mem,...
                else
                {
                    //cop Mem, Imm
                    if (DisInfo.OpType[1] == otIMM)
                    {
                        //cop [Offset], Imm
                        if (DisInfo.BaseReg == -1 && DisInfo.IndxReg == -1)
                        {
                            Adr = DisInfo.Offset;
                            if (IsValidImageAdr(Adr))
                            {
                                _ap = Adr2Pos(Adr);
                                if (_ap >= 0)
                                {
                                    recN1 = GetInfoRec(Adr);
                                    if (!recN1) recN1 = new InfoRec(_ap, ikData);
                                    MakeGvar(recN1, Adr, curAdr);
                                    if (!IsValidCodeAdr(Adr)) recN1->AddXref('C', fromAdr, curAdr - fromAdr);
                                }
                                else
                                {
                                    recN1 = AddToBSSInfos(Adr, MakeGvarName(Adr), "");
                                    if (recN1) recN1->AddXref('C', fromAdr, curAdr - fromAdr);
                                }
                            }
                        }
                        //cop [BaseReg + IndxReg*Scale + Offset], Imm
                        else if (DisInfo.BaseReg != -1)
                        {
                            //cop [BaseReg + Offset], Imm
                            if (DisInfo.IndxReg == -1)
                            {
                                //cop [rbp - Offset], Imm
                                if (bpBased && DisInfo.BaseReg == REG_RBP && (int)DisInfo.Offset < 0)
                                {
                                    recN1 = GetInfoRec(fromAdr);
                                    recN1->procInfo->AddLocal((int)DisInfo.Offset, DisInfo.OpSize, "", "");
                                }
                                //cop [rsp], Imm
                                else if (DisInfo.BaseReg == REG_RSP)
                                {
                                    dummy = 1;
                                }
                                //other registers
                                else
                                {
                                    //cop [BaseReg], Imm
                                    if (!DisInfo.Offset)
                                    {
                                        Adr = registers[DisInfo.BaseReg].value;
                                        if (IsValidImageAdr(Adr))
                                        {
                                            _ap = Adr2Pos(Adr);
                                            if (_ap >= 0)
                                            {
                                                recN = GetInfoRec(Adr);
                                                if (!recN) recN = new InfoRec(_ap, ikData);
                                                MakeGvar(recN, Adr, curAdr);
                                                if (!IsValidCodeAdr(Adr)) recN->AddXref('C', fromAdr, curAdr - fromAdr);
                                            }
                                            else
                                            {
                                                recN1 = AddToBSSInfos(Adr, MakeGvarName(Adr), "");
                                                if (recN1) recN1->AddXref('C', fromAdr, curAdr - fromAdr);
                                            }
                                        }
                                    }
                                    //cop [BaseReg + Offset], Imm
                                    else if ((int)DisInfo.Offset > 0)
                                    {
                                        typeName = TrimTypeName(registers[DisInfo.BaseReg].type);
                                        if (typeName != "")
                                        {
                                            fInfo = GetField(typeName, (int)DisInfo.Offset, &vmt, &vmtAdr);
                                            if (fInfo)
                                            {
                                                if (vmt)
                                                {
                                                    if (op != OP_CMP && op != OP_TEST)
                                                        AddFieldXref(fInfo, fromAdr, curAdr - fromAdr, 'c');
                                                    else
                                                        AddFieldXref(fInfo, fromAdr, curAdr - fromAdr, 'C');
                                                }
                                                else
                                                    delete fInfo;
                                                //if (vmtAdr) typeName = GetClsName(vmtAdr);
                                                AddPicode(curPos, 0, typeName, DisInfo.Offset);
                                            }
                                            else if (vmt)
                                            {
                                                fInfo = AddField(fromAdr, curAdr - fromAdr, typeName, FIELD_PUBLIC, (int)DisInfo.Offset, -1, "", sType);
                                                if (fInfo)
                                                {
                                                    if (op != OP_CMP && op != OP_TEST)
                                                        AddFieldXref(fInfo, fromAdr, curAdr - fromAdr, 'c');
                                                    else
                                                        AddFieldXref(fInfo, fromAdr, curAdr - fromAdr, 'C');
                                                	AddPicode(curPos, 0, typeName, DisInfo.Offset);
                                                }
                                            }
                                        }
                                    }
                                    //cop [BaseReg - Offset], Imm
                                    else
                                    {
                                    }
                                }
                            }
                            //cop [BaseReg + IndxReg*Scale + Offset], Imm
                            else
                            {
                            }
                        }
                        //Other instructions
                        else
                        {
                        }
                    }
                    //cop Mem, reg
                    else if (DisInfo.OpType[1] == otREG)
                    {
                        reg2Idx = DisInfo.OpRegIdx[1];
                        //op [Offset], reg
                        if (DisInfo.BaseReg == -1 && DisInfo.IndxReg == -1)
                        {
                            varAdr = DisInfo.Offset;
                            if (IsValidImageAdr(varAdr))
                            {
                                _ap = Adr2Pos(varAdr);
                                if (_ap >= 0)
                                {
                                    recN1 = GetInfoRec(varAdr);
                                    if (!recN1) recN1 = new InfoRec(_ap, ikData);
                                    MakeGvar(recN1, varAdr, curAdr);
                                    if (op == OP_MOV)
                                    {
                                        if (registers[reg2Idx].type != "") recN1->type = registers[reg2Idx].type;
                                    }
                                    if (!IsValidCodeAdr(varAdr)) recN1->AddXref('C', fromAdr, curAdr - fromAdr);
                                }
                                else
                                {
                                    recN1 = AddToBSSInfos(varAdr, MakeGvarName(varAdr), registers[reg2Idx].type);
                                    if (recN1) recN1->AddXref('C', fromAdr, curAdr - fromAdr);
                                }
                            }
                        }
                        //cop [BaseReg + IndxReg*Scale + Offset], reg
                        else if (DisInfo.BaseReg != -1)
                        {
                            if (DisInfo.IndxReg == -1)
                            {
                                //cop [rbp - Offset], reg
                                if (bpBased && DisInfo.BaseReg == REG_RBP && (int)DisInfo.Offset < 0)
                                {
                                    recN1 = GetInfoRec(fromAdr);
                                    recN1->procInfo->AddLocal((int)DisInfo.Offset, 4, "", registers[reg2Idx].type);
                                }
                                //rsp
                                else if (DisInfo.BaseReg == REG_RSP)
                                {
                                }
                                //other registers
                                else
                                {
                                    //cop [BaseReg], reg
                                    if (!DisInfo.Offset)
                                    {
                                        varAdr = registers[DisInfo.BaseReg].value;
                                        if (IsValidImageAdr(varAdr))
                                        {
                                            _ap = Adr2Pos(varAdr);
                                            if (_ap >= 0)
                                            {
                                                recN1 = GetInfoRec(varAdr);
                                                if (!recN1) recN1 = new InfoRec(_ap, ikData);
                                                MakeGvar(recN1, varAdr, curAdr);
                                                if (recN1->type == "") recN1->type = registers[reg2Idx].type;
                                                if (!IsValidCodeAdr(varAdr)) recN1->AddXref('C', fromAdr, curAdr - fromAdr);
                                            }
                                            else
                                            {
                                                recN1 = AddToBSSInfos(varAdr, MakeGvarName(varAdr), registers[reg2Idx].type);
                                                if (recN1) recN1->AddXref('C', fromAdr, curAdr - fromAdr);
                                            }
                                        }
                                        else
                                        {
                                            typeName = TrimTypeName(registers[DisInfo.BaseReg].type);
                                            if (typeName != "")
                                            {
                                                if (registers[reg2Idx].type != "") sType = registers[reg2Idx].type;
                                                fInfo = GetField(typeName, (int)DisInfo.Offset, &vmt, &vmtAdr);
                                                if (fInfo)
                                                {
                                                    if (vmt)
                                                    {
                                                        if (CanReplace(fInfo->Type, sType)) fInfo->Type = sType;
                                                        AddFieldXref(fInfo, fromAdr, curAdr - fromAdr, 'c');
                                                    }
                                                    else
                                                    {
                                                        delete fInfo;
                                                    }
                                                    AddPicode(curPos, 0, typeName, DisInfo.Offset);
                                                }
                                                else if (vmt)
                                                {
                                                    fInfo = AddField(fromAdr, curAdr - fromAdr, typeName, FIELD_PUBLIC, (int)DisInfo.Offset, -1, "", sType);
                                                    if (fInfo)
                                                    {
                                                        AddFieldXref(fInfo, fromAdr, curAdr - fromAdr, 'c');
                                                        AddPicode(curPos, 0, typeName, DisInfo.Offset);
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    //cop [BaseReg + Offset], reg
                                    else if ((int)DisInfo.Offset > 0)
                                    {
                                        typeName = TrimTypeName(registers[DisInfo.BaseReg].type);
                                        if (typeName != "")
                                        {
                                        	if (registers[reg2Idx].type != "") sType = registers[reg2Idx].type;
                                            fInfo = GetField(typeName, (int)DisInfo.Offset, &vmt, &vmtAdr);
                                            if (fInfo)
                                            {
                                                if (vmt)
                                                {
                                                    if (CanReplace(fInfo->Type, sType)) fInfo->Type = sType;
                                                    AddFieldXref(fInfo, fromAdr, curAdr - fromAdr, 'c');
                                                }
                                                else
                                                {
                                                    delete fInfo;
                                                }
                                                //if (vmtAdr) typeName = GetClsName(vmtAdr);
                                                AddPicode(curPos, 0, typeName, DisInfo.Offset);
                                            }
                                            else if (vmt)
                                            {
                                                fInfo = AddField(fromAdr, curAdr - fromAdr, typeName, FIELD_PUBLIC, (int)DisInfo.Offset, -1, "", sType);
                                                if (fInfo)
                                                {
                                                    AddFieldXref(fInfo, fromAdr, curAdr - fromAdr, 'c');
                                                	AddPicode(curPos, 0, typeName, DisInfo.Offset);
                                                }
                                            }
                                        }
                                    }
                                    //cop [BaseReg - Offset], reg
                                    else
                                    {
                                    }
                                }
                            }
                            //cop [BaseReg + IndxReg*Scale + Offset], reg
                            else
                            {
                                //cop [BaseReg + IndxReg*Scale + Offset], reg
                                if (bpBased && DisInfo.BaseReg == REG_RBP && (int)DisInfo.Offset < 0)
                                {
                                }
                                //rsp
                                else if (DisInfo.BaseReg == REG_RSP)
                                {
                                }
                                //other registers
                                else
                                {
                                    //[BaseReg]
                                    if (!DisInfo.Offset)
                                    {
                                    }
                                    //cop [BaseReg + IndxReg*Scale + Offset], reg
                                    else if ((int)DisInfo.Offset > 0)
                                    {
                                        typeName = TrimTypeName(registers[DisInfo.BaseReg].type);
                                    }
                                    //cop [BaseReg - Offset], reg
                                    else
                                    {
                                    }
                                }
                            }
                        }
                        //Other instructions
                        else
                        {
                        }
                    }
                }
            }
            else if (op == OP_ADC || op == OP_SBB)
            {
                if (DisInfo.OpType[0] == otREG)
                {
                    reg1Idx = DisInfo.OpRegIdx[0];
                    SetRegisterValue(registers, reg1Idx, -1);
                    registers[reg1Idx].type = "";
                }
            }
            else if (op == OP_MUL || op == OP_DIV)
            {
                //Clear register rax
                SetRegisterValue(registers, REG_RAX, -1);
                SetRegisterType(registers, REG_RAX, "");
                //Clear register rdx
                SetRegisterValue(registers, REG_RDX, -1);
                SetRegisterType(registers, REG_RDX, "");
            }
            else
            {
                if (DisInfo.OpType[0] == otREG)
                {
                    reg1Idx = DisInfo.OpRegIdx[0];
                    if ((registers[reg1Idx].source & 0xDF) != 'L')
                        SetRegisterValue(registers, reg1Idx, -1);
                    registers[reg1Idx].type = "";
                }
            }
            //SHL??? SHR???
        }
        curPos += instrLen; curAdr += instrLen;
    }
    return fContinue;
}
//---------------------------------------------------------------------------
String __fastcall Idr64Manager::AnalyzeCall(DWORD parentAdr, int callPos, DWORD callAdr, PRINFO registers)
{
    WORD        codePage, elemSize = 1;
    int         n, wBytes, pos, pushn, itemPos, refcnt, len, regIdx;
    int         _idx, _ap, _kind, _size, _pos;
    DWORD		itemAdr, strAdr;
    char        *tmpBuf;
    PInfoRec    recN, recN1;
    PARGINFO	argInfo;
    String      typeDef, typeName, retName, _vs;
    DISINFO		_disInfo;
    char        buf[1024];  //for LoadStr function

    _ap = Adr2Pos(callAdr);
    if (_ap < 0) return "";

    retName = "";
    recN = GetInfoRec(callAdr);
    //If procedure is skipped return
    if (IsFlagSet(cfSkip, callPos))
    {
        //@BeforeDestruction
        if (recN->SameName("@BeforeDestruction")) return registers[REG_RCX].type;

        return recN->type;
    }

    //cdecl, stdcall
    if (recN->procInfo->flags & 1)
    {
    	if (!recN->procInfo->args || !recN->procInfo->args->Count)
        {
            return recN->type;
        }

        for (pos = callPos, pushn = -1;; pos--)
        {
            if (!IsFlagSet(cfInstruction, pos)) continue;
            if (IsFlagSet(cfProcStart, pos)) break;
            //I cannot yet handle this situation
            if (IsFlagSet(cfCall, pos) && pos != callPos) break;
            if (IsFlagSet(cfPush, pos))
            {
                pushn++;
                if (pushn < recN->procInfo->args->Count)
                {
                    GetDisasm().Disassemble(Code + pos, (__int64)Pos2Adr(pos), &_disInfo, 0);
                    itemAdr = _disInfo.Immediate;
                    if (IsValidImageAdr(itemAdr))
                    {
                        itemPos = Adr2Pos(itemAdr);
                        argInfo = (PARGINFO)recN->procInfo->args->Items[pushn];
                        typeDef = argInfo->TypeDef;

                        if (SameText(typeDef, "PAnsiChar") || SameText(typeDef, "PChar"))
                        {
                            if (itemPos >= 0)
                            {
                                recN1 = GetInfoRec(itemAdr);
                                if (!recN1) recN1 = new InfoRec(itemPos, ikData);
                                //var - use pointer
                                if (argInfo->Tag == 0x22)
                                {
                                    strAdr = *((DWORD*)(Code + itemPos));
                                    if (!strAdr)
                                    {
                                        SetFlags(cfData, itemPos, 4);
                                        MakeGvar(recN1, itemAdr, Pos2Adr(pos));
                                        if (typeDef != "") recN1->type = typeDef;
                                    }
                                    else
                                    {
                                        _ap = Adr2Pos(strAdr);
                                        if (_ap >= 0)
                                        {
                                            len = strlen((char*)(Code + _ap));
                                            SetFlags(cfData, _ap, len + 1);
                                        }
                                        else if (_ap == -1)
                                        {
                                            recN1 = AddToBSSInfos(strAdr, MakeGvarName(strAdr), typeDef);
                                            if (recN1) recN1->AddXref('C', callAdr, callPos);
                                        }
                                    }
                                }
                                //val
                                else if (argInfo->Tag == 0x21)
                                {
                                    recN1->kind = ikCString;
                                    len = strlen(Code + itemPos);
                                    if (!recN1->HasName())
                                    {
                                        if (IsValidCodeAdr(itemAdr))
                                        {
                                            recN1->SetName(TransformString(Code + itemPos, len));
                                        }
                                        else
                                        {
                                            recN1->SetName(MakeGvarName(itemAdr));
                                            if (typeDef != "") recN1->type = typeDef;
                                        }
                                    }
                                    SetFlags(cfData, itemPos, len + 1);
                                }
                                if (recN1) recN1->ScanUpItemAndAddRef(callPos, itemAdr, 'C', parentAdr);
                            }
                            else
                            {
                                recN1 = AddToBSSInfos(itemAdr, MakeGvarName(itemAdr), typeDef);
                                if (recN1) recN1->AddXref('C', callAdr, callPos);
                            }
                        }
                        else if (SameText(typeDef, "PWideChar"))
                        {
                            if (itemPos)
                            {
                                recN1 = GetInfoRec(itemAdr);
                                if (!recN1) recN1 = new InfoRec(itemPos, ikData);
                                //var - use pointer
                                if (argInfo->Tag == 0x22)
                                {
                                    strAdr = *((DWORD*)(Code + itemPos));
                                    if (!strAdr)
                                    {
                                        SetFlags(cfData, itemPos, 4);
                                        MakeGvar(recN1, itemAdr, Pos2Adr(pos));
                                        if (typeDef != "") recN1->type = typeDef;
                                    }
                                    else
                                    {
                                        _ap = Adr2Pos(strAdr);
                                        if (_ap >= 0)
                                        {
                                            len = wcslen((wchar_t*)(Code + Adr2Pos(strAdr)));
                                            SetFlags(cfData, Adr2Pos(strAdr), 2*len + 1);
                                        }
                                        else if (_ap == -1)
                                        {
                                            recN1 = AddToBSSInfos(strAdr, MakeGvarName(strAdr), typeDef);
                                            if (recN1) recN1->AddXref('C', callAdr, callPos);
                                        }
                                    }
                                }
                                //val
                                else if (argInfo->Tag == 0x21)
                                {
                                    recN1->kind = ikWCString;
                                    len = wcslen((wchar_t*)(Code + itemPos));
                                    if (!recN1->HasName())
                                    {
                                        if (IsValidCodeAdr(itemAdr))
                                        {
                                            WideString wStr = WideString((wchar_t*)(Code + itemPos));
                                            int size = WideCharToMultiByte(CP_ACP, 0, wStr, len, 0, 0, 0, 0);
                                            if (size)
                                            {
                                                tmpBuf = new char[size + 1];
                                                WideCharToMultiByte(CP_ACP, 0, wStr, len, (LPSTR)tmpBuf, size, 0, 0);
                                                recN1->SetName(TransformString(tmpBuf, size));
                                                delete[] tmpBuf;
                                                if (recN->SameName("GetProcAddress")) retName = recN1->GetName();
                                            }
                                        }
                                        else
                                        {
                                            recN1->SetName(MakeGvarName(itemAdr));
                                            if (typeDef != "") recN1->type = typeDef;
                                        }
                                    }
                                    SetFlags(cfData, itemPos, 2*len + 1);
                                }
                                recN1->AddXref('C', callAdr, callPos);
                            }
                            else
                            {
                                recN1 = AddToBSSInfos(itemAdr, MakeGvarName(itemAdr), typeDef);
                                if (recN1) recN1->AddXref('C', callAdr, callPos);
                            }
                        }
                        else if (SameText(typeDef, "TGUID"))
                        {
                            if (itemPos)
                            {
                                recN1 = GetInfoRec(itemAdr);
                                if (!recN1) recN1 = new InfoRec(itemPos, ikGUID);
                                recN1->kind = ikGUID;
                                SetFlags(cfData, itemPos, 16);
                                if (!recN1->HasName())
                                {
                                    if (IsValidCodeAdr(itemAdr))
                                    {
                                        recN1->SetName(Guid2String(Code + itemPos));
                                    }
                                    else
                                    {
                                        recN1->SetName(MakeGvarName(itemAdr));
                                        if (typeDef != "") recN1->type = typeDef;
                                    }
                                }
                                recN1->AddXref('C', callAdr, callPos);
                            }
                            else
                            {
                                recN1 = AddToBSSInfos(itemAdr, MakeGvarName(itemAdr), typeDef);
                                if (recN1) recN1->AddXref('C', callAdr, callPos);
                            }
                        }
                    }
                    if (pushn == recN->procInfo->args->Count - 1) break;
                }
            }
        }
        return recN->type;
    }
    if (recN->HasName())
    {
        if (recN->SameName("LoadStr") || recN->SameName("FmtLoadStr") || recN->SameName("LoadResString"))
        {
            int ident = registers[REG_RCX].value;//???!!!
            if (ident != -1)
            {
                HINSTANCE hInst = LoadLibraryEx(SourceFile.c_str(), 0, LOAD_LIBRARY_AS_DATAFILE);
                if (hInst)
                {
                    int bytes = LoadString(hInst, (UINT)ident, buf, sizeof(buf));
                    if (bytes) AddPicode(callPos, OP_COMMENT, "'" + String(buf, bytes) + "'", 0);
                    FreeLibrary(hInst);
                }
            }
            return "";
        }
        if (recN->SameName("TApplication.CreateForm"))
        {
            DWORD vmtAdr = registers[REG_RDX].value + Vmt.SelfPtr;

            DWORD refAdr = registers[REG_R8].value;
            if (IsValidImageAdr(refAdr))
            {
                typeName = GetClsName(vmtAdr);
                _ap = Adr2Pos(refAdr);
                if (_ap >= 0)
                {
                    recN1 = GetInfoRec(refAdr);
                    if (!recN1) recN1 = new InfoRec(_ap, ikData);
                    MakeGvar(recN1, refAdr, 0);
                    if (typeName != "") recN1->type = typeName;
                }
                else
                {
                    recN1 = idr.GetBSSInfosRec(Val2Str8(refAdr));
                    if (recN1)
                    {
                        if (typeName != "") recN1->type = typeName;
                    }
                }
            }
            return "";
        }
        if (recN->SameName("@FinalizeRecord"))
        {
            DWORD recAdr = registers[REG_RCX].value;
            DWORD recTypeAdr = registers[REG_RDX].value;
            typeName = GetTypeName(recTypeAdr);
            //Address given directly
            if (IsValidImageAdr(recAdr))
            {
                _ap = Adr2Pos(recAdr);
                if (_ap >= 0)
                {
                    recN1 = GetInfoRec(recAdr);
                    if (!recN1) recN1 = new InfoRec(_ap, ikRecord);
                    MakeGvar(recN1, recAdr, 0);
                    if (typeName != "") recN1->type = typeName;
                    if (!IsValidCodeAdr(recAdr)) recN1->AddXref('C', callAdr, callPos);
                }
                else
                {
                    recN1 = AddToBSSInfos(recAdr, MakeGvarName(recAdr), typeName);
                    if (recN1) recN1->AddXref('C', callAdr, callPos);
                }
            }
            //Local variable
            else if ((registers[REG_RCX].source & 0xDF) == 'L')
            {
                if (registers[REG_RCX].type == "" && typeName != "") registers[REG_RCX].type = typeName;
                registers[REG_RCX].result = 1;
            }
            return "";
        }
        if (recN->SameName("@DynArrayAddRef"))
        {
            DWORD arrayAdr = registers[REG_RCX].value;
            //Address given directly
            if (IsValidImageAdr(arrayAdr))
            {
                _ap = Adr2Pos(arrayAdr);
                if (_ap >= 0)
                {
                    recN1 = GetInfoRec(arrayAdr);
                    if (!recN1) recN1 = new InfoRec(_ap, ikDynArray);
                    MakeGvar(recN1, arrayAdr, 0);
                    if (!IsValidCodeAdr(arrayAdr)) recN1->AddXref('C', callAdr, callPos);
                }
                else
                {
                    recN1 = AddToBSSInfos(arrayAdr, MakeGvarName(arrayAdr), "");
                    if (recN1) recN1->AddXref('C', callAdr, callPos);
                }
            }
            //Local variable
            else if ((registers[REG_RCX].source & 0xDF) == 'L')
            {
                if (registers[REG_RCX].type == "") registers[REG_RCX].type = "array of ?";
                registers[REG_RCX].result = 1;
            }
            return "";
        }
        if (recN->SameName("DynArrayClear")     ||
            recN->SameName("@DynArrayClear")    ||
            recN->SameName("DynArraySetLength") ||
            recN->SameName("@DynArraySetLength"))
        {
            DWORD arrayAdr = registers[REG_RCX].value;
            DWORD elTypeAdr = registers[REG_RDX].value;
            typeName = GetTypeName(elTypeAdr);
            //Address given directly
            if (IsValidImageAdr(arrayAdr))
            {
                _ap = Adr2Pos(arrayAdr);
                if (_ap >= 0)
                {
                    recN1 = GetInfoRec(arrayAdr);
                    if (!recN1) recN1 = new InfoRec(_ap, ikDynArray);
                    MakeGvar(recN1, arrayAdr, 0);
                    if (recN1->type == "" && typeName != "") recN1->type = typeName;
                    if (!IsValidCodeAdr(arrayAdr)) recN1->AddXref('C', callAdr, callPos);
                }
                else
                {
                    recN1 = AddToBSSInfos(arrayAdr, MakeGvarName(arrayAdr), typeName);
                    if (recN1) recN1->AddXref('C', callAdr, callPos);
                }
            }
            //Local variable
            else if ((registers[REG_RCX].source & 0xDF) == 'L')
            {
                if (registers[REG_RCX].type == "" && typeName != "") registers[REG_RCX].type = typeName;
                registers[REG_RCX].result = 1;
            }
            return "";
        }
        if (recN->SameName("@DynArrayCopy"))
        {
            DWORD arrayAdr = registers[REG_RDX].value;
            DWORD elTypeAdr = registers[REG_R8].value;
            DWORD dstArrayAdr = registers[REG_RCX].value;
            typeName = GetTypeName(elTypeAdr);
            //Address given directly
            if (IsValidImageAdr(arrayAdr))
            {
                _ap = Adr2Pos(arrayAdr);
                if (_ap >= 0)
                {
                    recN1 = GetInfoRec(arrayAdr);
                    if (!recN1) recN1 = new InfoRec(_ap, ikDynArray);
                    MakeGvar(recN1, arrayAdr, 0);
                    if (typeName != "") recN1->type = typeName;
                    if (!IsValidCodeAdr(arrayAdr)) recN1->AddXref('C', callAdr, callPos);
                }
                else
                {
                    recN1 = AddToBSSInfos(arrayAdr, MakeGvarName(arrayAdr), typeName);
                    if (recN1) recN1->AddXref('C', callAdr, callPos);
                }
            }
            //Local variable
            else if ((registers[REG_RDX].source & 0xDF) == 'L')
            {
                if (registers[REG_RDX].type == "" && typeName != "") registers[REG_RDX].type = typeName;
                registers[REG_RDX].result = 1;
            }
            //Address given directly
            if (IsValidImageAdr(dstArrayAdr))
            {
                _ap = Adr2Pos(dstArrayAdr);
                if (_ap >= 0)
                {
                    recN1 = GetInfoRec(dstArrayAdr);
                    if (!recN1) recN1 = new InfoRec(_ap, ikDynArray);
                    MakeGvar(recN1, dstArrayAdr, 0);
                    if (typeName != "") recN1->type = typeName;
                    if (!IsValidCodeAdr(dstArrayAdr)) recN1->AddXref('C', callAdr, callPos);
                }
                else
                {
                    recN1 = AddToBSSInfos(dstArrayAdr, MakeGvarName(dstArrayAdr), typeName);
                    if (recN1) recN1->AddXref('C', callAdr, callPos);
                }
            }
            //Local variable
            else if ((registers[REG_RDX].source & 0xDF) == 'L')
            {
                if (registers[REG_RDX].type == "" && typeName != "") registers[REG_RDX].type = typeName;
                registers[REG_RDX].result = 1;
            }
            return "";
        }
        if (recN->SameName("@IntfClear"))
        {
            DWORD intfAdr = registers[REG_RCX].value;

            if (IsValidImageAdr(intfAdr))
            {
                _ap = Adr2Pos(intfAdr);
                if (_ap >= 0)
                {
                    recN1 = GetInfoRec(intfAdr);
                    if (!recN1) recN1 = new InfoRec(_ap, ikInterface);
                    MakeGvar(recN1, intfAdr, 0);
                    recN1->type = "IInterface";
                    if (!IsValidCodeAdr(intfAdr)) recN1->AddXref('C', callAdr, callPos);
                }
                else
                {
                    recN1 = AddToBSSInfos(intfAdr, MakeGvarName(intfAdr), "IInterface");
                    if (recN1) recN1->AddXref('C', callAdr, callPos);
                }
            }
            return "";
        }
        if (recN->SameName("@FinalizeArray"))
        {
            DWORD arrayAdr = registers[REG_RCX].value;
            int elNum = registers[REG_R8].value;
            DWORD elTypeAdr = registers[REG_RDX].value;

            if (IsValidImageAdr(arrayAdr))
            {
                typeName = "array[" + String(elNum) + "] of " + GetTypeName(elTypeAdr);
                _ap = Adr2Pos(arrayAdr);
                if (_ap >= 0)
                {
                    recN1 = GetInfoRec(arrayAdr);
                    if (!recN1) recN1 = new InfoRec(_ap, ikArray);
                    MakeGvar(recN1, arrayAdr, 0);
                    recN1->type = typeName;
                    if (!IsValidCodeAdr(arrayAdr)) recN1->AddXref('C', callAdr, callPos);
                }
                else
                {
                    recN1 = AddToBSSInfos(arrayAdr, MakeGvarName(arrayAdr), typeName);
                    if (recN1) recN1->AddXref('C', callAdr, callPos);
                }
            }
            return "";
        }
        if (recN->SameName("@VarClr"))
        {
            DWORD strAdr = registers[REG_RCX].value;
            if (IsValidImageAdr(strAdr))
            {
                _ap = Adr2Pos(strAdr);
                if (_ap >= 0)
                {
                    recN1 = GetInfoRec(strAdr);
                    if (!recN1) recN1 = new InfoRec(_ap, ikVariant);
                    MakeGvar(recN1, strAdr, 0);
                    recN1->type = "Variant";
                    if (!IsValidCodeAdr(strAdr)) recN1->AddXref('C', callAdr, callPos);
                }
                else
                {
                    recN1 = AddToBSSInfos(strAdr, MakeGvarName(strAdr), "Variant");
                    if (recN1) recN1->AddXref('C', callAdr, callPos);
                }
            }
            return "";
        }
        //@AsClass
        if (recN->SameName("@AsClass"))
        {
            return registers[REG_RDX].type;
        }
        //@IsClass
        if (recN->SameName("@IsClass"))
        {
            return "";
        }
        //@GetTls
        if (recN->SameName("@GetTls"))
        {
            return "#TLS";
        }
        //@AfterConstruction
        if (recN->SameName("@AfterConstruction")) return "";
    }
    //try prototype
    BYTE callKind = recN->procInfo->flags & 7;
    if (recN->procInfo->args && !callKind)
    {
        registers[REG_RCX].result = 0;
        registers[REG_RDX].result = 0;
        registers[REG_R8].result = 0;
        registers[REG_R9].result = 0;

        for (n = 0; n < recN->procInfo->args->Count; n++)
        {
            argInfo = (PARGINFO)recN->procInfo->args->Items[n];
            regIdx = -1;
            if (argInfo->Ndx == 0)
                regIdx = REG_RCX;
            else if (argInfo->Ndx == 1)
                regIdx = REG_RDX;
            else if (argInfo->Ndx == 2)
                regIdx = REG_R8;
            else if (argInfo->Ndx == 3)
                regIdx = REG_R9;
            if (regIdx == -1) continue;

            if (argInfo->TypeDef == "")
            {
            	if (registers[regIdx].type != "")
                    argInfo->TypeDef = TrimTypeName(registers[regIdx].type);
            }
            else
            {
            	if (registers[regIdx].type == "")
                {
                    registers[regIdx].type = argInfo->TypeDef;
                    //registers[regIdx].result = 1;
                }
                else
                {
                	typeName = GetCommonType(argInfo->TypeDef, TrimTypeName(registers[regIdx].type));
                    if (typeName != "") argInfo->TypeDef = typeName;
                }
                //Aliases ???????????
            }

            typeDef = argInfo->TypeDef;
            //Local var (lea - remove ^ before type)
            if (registers[regIdx].source == 'L')
            {
            	if (SameText(typeDef, "Pointer"))
                	registers[regIdx].type = "Byte";
                else if (SameText(typeDef, "PAnsiChar") || SameText(typeDef, "PChar"))
                    registers[regIdx].type = typeDef.SubString(2, typeDef.Length() - 1);
                else if (SameText(typeDef, "AnsiString"))
                	registers[regIdx].type = "UnicodeString";

                registers[regIdx].result = 1;
                continue;
            }
            //Local var
            if (registers[regIdx].source == 'l')
            {
            	continue;
            }
            //Arg
            if ((registers[regIdx].source & 0xDF) == 'A')
            {
                continue;
            }
            itemAdr = registers[regIdx].value;
            if (IsValidImageAdr(itemAdr))
            {
                itemPos = Adr2Pos(itemAdr);
                if (itemPos >= 0)
                {
                    recN1 = GetInfoRec(itemAdr);
                    if (!recN1 || recN1->kind != ikVMT)
                    {
                        registers[regIdx].result = 1;

                        if (SameText(typeDef, "PShortString") || SameText(typeDef, "ShortString"))
                        {
                            recN1 = GetInfoRec(itemAdr);
                            if (!recN1) recN1 = new InfoRec(itemPos, ikData);
                            //var - use pointer
                            if (argInfo->Tag == 0x22)
                            {
                                strAdr = *((DWORD*)(Code + itemPos));
                                if (IsValidCodeAdr(strAdr))
                                {
                                    _ap = Adr2Pos(strAdr);
                                    len = *(Code + _ap);
                                    SetFlags(cfData, _ap, len + 1);
                                }
                                else
                                {
                                    SetFlags(cfData, itemPos, 4);
                                    MakeGvar(recN1, itemAdr, 0);
                                    if (typeDef != "") recN1->type = typeDef;
                                }
                            }
                            //val
                            else if (argInfo->Tag == 0x21)
                            {
                                recN1->kind = ikString;
                                len = *(Code + itemPos);
                                if (!recN1->HasName())
                                {
                                    if (IsValidCodeAdr(itemAdr))
                                    {
                                        recN1->SetName(TransformString(Code + itemPos + 1, len));
                                    }
                                    else
                                    {
                                        recN1->SetName(MakeGvarName(itemAdr));
                                        if (typeDef != "") recN1->type = typeDef;
                                    }
                                }
                                SetFlags(cfData, itemPos, len + 1);
                            }
                        }
                        else if (SameText(typeDef, "PAnsiChar") || SameText(typeDef, "PChar"))
                        {
                            recN1 = GetInfoRec(itemAdr);
                            if (!recN1) recN1 = new InfoRec(itemPos, ikData);
                            //var - use pointer
                            if (argInfo->Tag == 0x22)
                            {
                                strAdr = *((DWORD*)(Code + itemPos));
                                if (IsValidCodeAdr(strAdr))
                                {
                                    _ap = Adr2Pos(strAdr);
                                    len = strlen(Code + _ap);
                                    SetFlags(cfData, _ap, len + 1);
                                }
                                else
                                {
                                    SetFlags(cfData, itemPos, 4);
                                    MakeGvar(recN1, itemAdr, 0);
                                    if (typeDef != "") recN1->type = typeDef;
                                }
                            }
                            //val
                            else if (argInfo->Tag == 0x21)
                            {
                                recN1->kind = ikCString;
                                len = strlen(Code + itemPos);
                                if (!recN1->HasName())
                                {
                                    if (IsValidCodeAdr(itemAdr))
                                    {
                                        recN1->SetName(TransformString(Code + itemPos, len));
                                    }
                                    else
                                    {
                                        recN1->SetName(MakeGvarName(itemAdr));
                                        if (typeDef != "") recN1->type = typeDef;
                                    }
                                }
                                SetFlags(cfData, itemPos, len + 1);
                            }
                        }
                        else if (SameText(typeDef, "AnsiString") ||
                                 SameText(typeDef, "String")     ||
                                 SameText(typeDef, "UString")    ||
                                 SameText(typeDef, "UnicodeString"))
                        {
                            recN1 = GetInfoRec(itemAdr);
                            if (!recN1) recN1 = new InfoRec(itemPos, ikData);
                            //var - use pointer
                            if (argInfo->Tag == 0x22)
                            {
                                strAdr = *((DWORD*)(Code + itemPos));
                                _ap = Adr2Pos(strAdr);
                                if (IsValidCodeAdr(strAdr))
                                {
                                    refcnt = *((int*)(Code + _ap - 8));
                                    len = *((int*)(Code + _ap - 4));
                                    if (refcnt == -1 && len >= 0 && len < 25000)
                                    {
                                        codePage = *((WORD*)(Code + _ap - 12));
                                        elemSize = *((WORD*)(Code + _ap - 10));
                                        SetFlags(cfData, _ap - 12, (12 + (len + 1)*elemSize + 3) & (-4));
                                    }
                                    else
                                    {
                                        SetFlags(cfData, _ap, 4);
                                    }
                                }
                                else
                                {
                                    if (_ap >= 0)
                                    {
                                        SetFlags(cfData, itemPos, 4);
                                        MakeGvar(recN1, itemAdr, 0);
                                        if (typeDef != "") recN1->type = typeDef;
                                    }
                                    else if (_ap == -1)
                                    {
                                        recN1 = AddToBSSInfos(itemAdr, MakeGvarName(itemAdr), typeDef);
                                    }
                                }
                            }
                            //val
                            else if (argInfo->Tag == 0x21)
                            {
                                refcnt = *((int*)(Code + itemPos - 8));
                                len = wcslen((wchar_t*)(Code + itemPos));
                                codePage = *((WORD*)(Code + itemPos - 12));
                                elemSize = *((WORD*)(Code + itemPos - 10));
                                recN1->kind = ikUString;
                                if (refcnt == -1 && len >= 0 && len < 25000)
                                {
                                    if (!recN1->HasName())
                                    {
                                        if (IsValidCodeAdr(itemAdr))
                                        {
                                            recN1->SetName(TransformUString(codePage, (wchar_t*)(Code + itemPos), len));
                                        }
                                        else
                                        {
                                            recN1->SetName(MakeGvarName(itemAdr));
                                            if (typeDef != "") recN1->type = typeDef;
                                        }
                                    }
                                    SetFlags(cfData, itemPos - 12, (12 + (len + 1)*elemSize + 3) & (-4));
                                }
                                else
                                {
                                    if (!recN1->HasName())
                                    {
                                        if (IsValidCodeAdr(itemAdr))
                                        {
                                            recN1->SetName("");
                                        }
                                        else
                                        {
                                            recN1->SetName(MakeGvarName(itemAdr));
                                            if (typeDef != "") recN1->type = typeDef;
                                        }
                                    }
                                    SetFlags(cfData, itemPos, 4);
                                }
                            }
                        }
                        else if (SameText(typeDef, "WideString"))
                        {
                            recN1 = GetInfoRec(itemAdr);
                            if (!recN1) recN1 = new InfoRec(itemPos, ikData);
                            //var - use pointer
                            if (argInfo->Tag == 0x22)
                            {
                                strAdr = *((DWORD*)(Code + itemPos));
                                _ap = Adr2Pos(strAdr);
                                if (IsValidCodeAdr(strAdr))
                                {
                                    len = *((int*)(Code + _ap - 4));
                                    SetFlags(cfData, _ap - 4, (4 + len + 1 + 3) & (-4));
                                }
                                else
                                {
                                    if (_ap >= 0)
                                    {
                                        SetFlags(cfData, itemPos, 4);
                                        MakeGvar(recN1, itemAdr, 0);
                                        if (typeDef != "") recN1->type = typeDef;
                                    }
                                    else if (_ap == -1)
                                    {
                                        recN1 = AddToBSSInfos(itemAdr, MakeGvarName(itemAdr), typeDef);
                                    }
                                }
                            }
                            //val
                            else if (argInfo->Tag == 0x21)
                            {
                                recN1->kind = ikWString;
                                len = wcslen((wchar_t*)(Code + itemPos));
                                if (!recN1->HasName())
                                {
                                    if (IsValidCodeAdr(itemAdr))
                                    {
                                        WideString wStr = WideString((wchar_t*)(Code + itemPos));
                                        int size = WideCharToMultiByte(CP_ACP, 0, wStr, len, 0, 0, 0, 0);
                                        if (size)
                                        {
                                            tmpBuf = new BYTE[size + 1];
                                            WideCharToMultiByte(CP_ACP, 0, wStr, len, (LPSTR)tmpBuf, size, 0, 0);
                                            recN1->SetName(TransformString(tmpBuf, size));    //???size - 1
                                            delete[] tmpBuf;
                                        }
                                    }
                                    else
                                    {
                                        recN1->SetName(MakeGvarName(itemAdr));
                                        if (typeDef != "") recN1->type = typeDef;
                                    }
                                }
                                SetFlags(cfData, itemPos - 4, (4 + len + 1 + 3) & (-4));
                            }
                        }
                        else if (SameText(typeDef, "TGUID"))
                        {
                            recN1 = GetInfoRec(itemAdr);
                            if (!recN1) recN1 = new InfoRec(itemPos, ikGUID);
                            recN1->kind = ikGUID;
                            SetFlags(cfData, itemPos, 16);
                            if (!recN1->HasName())
                            {
                                if (IsValidCodeAdr(itemAdr))
                                {
                                    recN1->SetName(Guid2String(Code + itemPos));
                                }
                                else
                                {
                                    recN1->SetName(MakeGvarName(itemAdr));
                                    if (typeDef != "") recN1->type = typeDef;
                                }
                            }
                        }
                        else if (SameText(typeDef, "PResStringRec"))
                        {
                            recN1 = GetInfoRec(itemAdr);
                            if (!recN1)
                            {
                                recN1 = new InfoRec(itemPos, ikResString);
                                recN1->type = "TResStringRec";
                                recN1->ConcatName("SResString" + String(LastResStrNo));
                                LastResStrNo++;
                                //Set Flags
                                SetFlags(cfData, itemPos, 8);
                                //Get Context
                                HINSTANCE hInst = LoadLibraryEx(SourceFile.c_str(), 0, LOAD_LIBRARY_AS_DATAFILE);
                                if (hInst)
                                {
                                    DWORD resid = *((DWORD*)(Code + itemPos + 4));
                                    if (resid < 0x10000)
                                    {
                                        int Bytes = LoadString(hInst, (UINT)resid, buf, sizeof(buf));
                                        recN1->rsInfo->value = String(buf, Bytes);
                                    }
                                    FreeLibrary(hInst);
                                }
                            }
                        }
                        else
                        {
                            recN1 = GetInfoRec(itemAdr);
                            if (!recN1) recN1 = new InfoRec(itemPos, ikData);
                            if (!recN1->HasName()            &&
                                recN1->kind != ikProc        &&
                                recN1->kind != ikFunc        &&
                                recN1->kind != ikConstructor &&
                                recN1->kind != ikDestructor  &&
                                recN1->kind != ikRefine)
                            {
                                if (typeDef != "") recN1->type = typeDef;
                            }
                        }
                    }
                }
                else
                {
                    _kind = GetTypeKind(typeDef, &_size);
                    if (_kind == ikInteger     ||
                        _kind == ikChar        ||
                        _kind == ikEnumeration ||
                        _kind == ikFloat       ||
                        _kind == ikSet         ||
                        _kind == ikWChar)
                    {
                        _idx = BSSInfos->IndexOf(Val2Str8(itemAdr));
                        if (_idx != -1)
                        {
                            recN1 = (PInfoRec)BSSInfos->Objects[_idx];
                            delete recN1;
                            BSSInfos->Delete(_idx);
                        }
                    }
                    else
                    {
                        recN1 = AddToBSSInfos(itemAdr, MakeGvarName(itemAdr), typeDef);
                    }
                }
            }
        }
    }
    if (recN->kind == ikFunc)
    {
        return recN->type;
    }
    return "";
}
//---------------------------------------------------------------------------
