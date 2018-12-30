//---------------------------------------------------------------------------
#include <vcl.h>
#pragma hdrstop

#include "Threads.h"
#include "Misc.h"
#include "KnowledgeBase.h"
#include "Resources.h"

//---------------------------------------------------------------------------
extern  MKnowledgeBase  KnowledgeBase;
//extern  TResourceInfo   *ResInfo;

//as: todo: remove all the global external dependencies
//    all the required vars should be passed into the thread

extern  int         dummy;
extern  DWORD       CurProcAdr;
extern  SysProcInfo SysProcs[];
extern  SysProcInfo SysInitProcs[];
extern  BYTE        *Code;
extern  DWORD       CodeSize;
//extern  DWORD       CodeBase;
extern  DWORD       TotalSize;
//extern  PInfoRec    *Infos;
extern  TList       *OwnTypeList;
//extern  int         VmtSelfPtr;
//extern  int         VmtInitTable;
//extern  int         VmtInstanceSize;
//extern  int         VmtParent;
//extern  int         VmtMethodTable;
//extern  int         VmtDynamicTable;
//extern  int         VmtTypeInfo;
//extern  int         VmtDestroy;

extern  int         UnitsNum;
extern  TList       *VmtList;
extern  TList       *Units;
extern  TStringList *PossibleUnitNames;
extern  DWORD       EP;
extern  DWORD       HInstanceVarAdr;
extern  int         LastResStrNo;
//extern  MDisasm     Disasm;
extern  String      SourceFile;

//as: print every 10th address in status bar (analysis time booster)
static const int SKIPADDR_COUNT = 10;


static int cntProgress = 0;

//---------------------------------------------------------------------------
__fastcall TAnalyzeThread::TAnalyzeThread(/*TFMain_11011981* */ HWND AForm, /*TFProgressBar* */ HWND ApbForm, bool AllValues)
    : TThread(true)
{
    Priority = tpLower;
    mainFormHandle = AForm;
    pbFormHandle = ApbForm; 
    all = AllValues;
    adrCnt = 0;
    cntProgress = 0;
}
//---------------------------------------------------------------------------
__fastcall TAnalyzeThread::~TAnalyzeThread()
{
}
//---------------------------------------------------------------------------
int __fastcall TAnalyzeThread::GetRetVal()
{
    return ReturnValue;
}
//---------------------------------------------------------------------------
//PopupMenu items!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
//The Execute method is called when the thread starts
void __fastcall TAnalyzeThread::Execute()
{
    try
    {
        if (all)
        {
            //1
            StrapSysProcs();
            ReturnValue = 1;
            CurProcAdr = EP;
            UpdateCode();
            //2
            FindRTTIs();
            ReturnValue = 2;
            UpdateUnits();
            //3
            FindVMTs();
            ReturnValue = 3;
            UpdateVmtList();
            UpdateRTTIs();
            UpdateCode();
            //4
            StrapVMTs();
            ReturnValue = 4;
            UpdateCode();
            //5
            ScanCode();
            ReturnValue = 5;
            UpdateCode();
            UpdateStrings();
            //6
            ScanVMTs();
            ReturnValue = 6;
            UpdateVmtList();
            UpdateCode();
            UpdateStrings();
            UpdateShortClassViewer();
            //7
            ScanConsts();
            ReturnValue = 7;
            UpdateUnits();
            //8
            ScanGetSetStoredProcs();
            ReturnValue = 8;
            //9
            FindStrings();
            ReturnValue = 9;
            //10
            AnalyzeCode1();
            ReturnValue = 10;
            UpdateCode();
            UpdateXrefs();
            //11
            ScanCode1();
            ReturnValue = 11;
            UpdateCode();
            //12
            PropagateClassProps();
            ReturnValue = 12;
            UpdateCode();
            //13
            FindTypeFields();
            ReturnValue = 13;
            UpdateCode();
            //14
            FindPrototypes();
            ReturnValue = 14;
            UpdateCode();
            //15
            AnalyzeCode2(true);
            ReturnValue = 15;
            UpdateCode();
            UpdateStrings();
            //16
            AnalyzeDC();
            ReturnValue = 16;
            UpdateCode();
            //17
            AnalyzeCode2(false);
            ReturnValue = 17;
            UpdateCode();
            UpdateStrings();
            //18
            AnalyzeDC();
            ReturnValue = 18;
            UpdateCode();
            //19
            AnalyzeCode2(false);
            ReturnValue = LAST_ANALYZE_STEP;
            UpdateCode();
            UpdateStrings();

            UpdateBeforeClassViewer();
        }
        //20
        //FillClassViewer();
        ReturnValue = LAST_ANALYZE_STEP + 1;
        UpdateClassViewer();
    }
    catch (Exception& e)
    {
        Application->ShowException(&e);
    }

    //update main wnd about operation over
    //only Post() here!) - async, otehrwise deadlock!
    ::PostMessage(mainFormHandle, WM_UPDANALYSISSTATUS, (int)taFinished, 0);
    TRACE("TAnalyzeThread::Execute() done, taFinished sent");
}
//---------------------------------------------------------------------------
const int PB_MAX_STEPS = 2048;
int __fastcall TAnalyzeThread::StartProgress(int pbMaxCount, const String& sbText)
{
    int stepSize = 1;
    int pbSteps = pbMaxCount / stepSize;
    if (pbSteps * stepSize < pbMaxCount) pbSteps++;

    if (pbMaxCount > PB_MAX_STEPS)
    {
        stepSize = 256;
        while (pbSteps > PB_MAX_STEPS)
        {
            stepSize *= 2;
            pbSteps = pbMaxCount / stepSize;
            if (pbSteps * stepSize < pbMaxCount) pbSteps++;
        }
    }
    ThreadAnalysisData* startOperation = new ThreadAnalysisData(pbSteps, sbText);
    ::SendMessage(pbFormHandle, WM_UPDANALYSISSTATUS, (int)taStartPrBar, (long)startOperation);//Post

    //debug
    ++cntProgress;
    TRACE("StartProgress %d, maxcnt %d for [%s]", cntProgress, pbMaxCount, sbText.c_str());
    //~

    return stepSize - 1;
}
//---------------------------------------------------------------------------
void __fastcall TAnalyzeThread::UpdateProgress()
{
    if (!Terminated)
        ::SendMessage(pbFormHandle, WM_UPDANALYSISSTATUS, (int)taUpdatePrBar, 0);//Post
}
//---------------------------------------------------------------------------
void __fastcall TAnalyzeThread::StopProgress()
{
    TRACE("StopProgress %d", cntProgress);
}
//---------------------------------------------------------------------------
void __fastcall TAnalyzeThread::UpdateStatusBar(int adr)
{
    if (!Terminated)
    {
        ThreadAnalysisData* updateStatusBar = new ThreadAnalysisData(0, Val2Str8(adr));
        ::SendMessage(pbFormHandle, WM_UPDANALYSISSTATUS, (int)taUpdateStBar, (long)updateStatusBar);
    }
}
//---------------------------------------------------------------------------
void __fastcall TAnalyzeThread::UpdateStatusBar(const String& sbText)
{
    if (!Terminated)
    {
        ThreadAnalysisData* updateStatusBar = new ThreadAnalysisData(0, sbText);
        ::SendMessage(pbFormHandle, WM_UPDANALYSISSTATUS, (int)taUpdateStBar, (long)updateStatusBar);
    }
}
//---------------------------------------------------------------------------
void __fastcall TAnalyzeThread::UpdateAddrInStatusBar(DWORD adr)
{
    if (!Terminated)
    {
        adrCnt++;
        if (adrCnt == SKIPADDR_COUNT)
        {
            UpdateStatusBar(adr);
            adrCnt = 0;
        }
    }
}
//---------------------------------------------------------------------------
void __fastcall TAnalyzeThread::UpdateUnits()
{
    if (!Terminated)
    {
        long isLastStep = long(ReturnValue == LAST_ANALYZE_STEP);
        ::SendMessage(mainFormHandle, WM_UPDANALYSISSTATUS, (int)taUpdateUnits, isLastStep);
    }
}
//---------------------------------------------------------------------------
void __fastcall TAnalyzeThread::UpdateRTTIs()
{
    if (!Terminated)
        ::SendMessage(mainFormHandle, WM_UPDANALYSISSTATUS, (int)taUpdateRTTIs, 0);
}
//---------------------------------------------------------------------------
void __fastcall TAnalyzeThread::UpdateVmtList()
{
    if (!Terminated)
        ::SendMessage(mainFormHandle, WM_UPDANALYSISSTATUS, (int)taUpdateVmtList, 0);
}
//---------------------------------------------------------------------------
void __fastcall TAnalyzeThread::UpdateStrings()
{
    if (!Terminated)
        ::SendMessage(mainFormHandle, WM_UPDANALYSISSTATUS, (int)taUpdateStrings, 0);
}
//---------------------------------------------------------------------------
void __fastcall TAnalyzeThread::UpdateCode()
{
    if (!Terminated)
    {
        UpdateUnits();
        //cant use Post here, there are some global shared vars!
        ::SendMessage(mainFormHandle, WM_UPDANALYSISSTATUS, (int)taUpdateCode, 0);
    }
}
//---------------------------------------------------------------------------
void __fastcall TAnalyzeThread::UpdateXrefs()
{
    if (!Terminated)
        ::SendMessage(mainFormHandle, WM_UPDANALYSISSTATUS, (int)taUpdateXrefs, 0);
}
//---------------------------------------------------------------------------
void __fastcall TAnalyzeThread::UpdateShortClassViewer()
{
    if (!Terminated)
        ::SendMessage(mainFormHandle, WM_UPDANALYSISSTATUS, (int)taUpdateShortClassViewer, 0);
}
//---------------------------------------------------------------------------
void __fastcall TAnalyzeThread::UpdateClassViewer()
{
    if (!Terminated)
        ::SendMessage(mainFormHandle, WM_UPDANALYSISSTATUS, (int)taUpdateClassViewer, 0);
}
//---------------------------------------------------------------------------
void __fastcall TAnalyzeThread::UpdateBeforeClassViewer()
{
    if (!Terminated)
        ::SendMessage(mainFormHandle, WM_UPDANALYSISSTATUS, (int)taUpdateBeforeClassViewer, 0);
}
//---------------------------------------------------------------------------
void __fastcall TAnalyzeThread::StrapSysProcs()
{
    int         n, Idx, pos;
    MProcInfo   aInfo, *pInfo;

    WORD moduleID = KnowledgeBase.GetModuleID("System");
    for (n = 0; n < SYSPROCSNUM && !Terminated; n++)
    {
        Idx = KnowledgeBase.GetProcIdx(moduleID, SysProcs[n].name);
        if (Idx != -1)
        {
            Idx = KnowledgeBase.ProcOffsets[Idx].NamId;
            if (!KnowledgeBase.IsUsedProc(Idx))
            {
                pInfo = KnowledgeBase.GetProcInfo(Idx, INFO_DUMP | INFO_ARGS, &aInfo);
                if (SysProcs[n].impAdr)
                {
                    StrapProc(Adr2Pos(SysProcs[n].impAdr), Idx, pInfo, false, 6);
                }
                else
                {
                    pos = KnowledgeBase.ScanCode(Code, idr.Flags, CodeSize, pInfo);
                    if (pInfo && pos != -1)
                    {
                        StrapProc(pos, Idx, pInfo, true, pInfo->DumpSz);
                    }
                }
            }
        }
    }

    moduleID = KnowledgeBase.GetModuleID("SysInit");
    for (n = 0; n < SYSINITPROCSNUM && !Terminated; n++)
    {
        Idx = KnowledgeBase.GetProcIdx(moduleID, SysInitProcs[n].name);
        if (Idx != -1)
        {
            Idx = KnowledgeBase.ProcOffsets[Idx].NamId;
            if (!KnowledgeBase.IsUsedProc(Idx))
            {
                pInfo = KnowledgeBase.GetProcInfo(Idx, INFO_DUMP | INFO_ARGS, &aInfo);
                pos = KnowledgeBase.ScanCode(Code, idr.Flags, CodeSize, pInfo);
                if (pInfo && pos != -1)
                {
                    StrapProc(pos, Idx, pInfo, true, pInfo->DumpSz);
                }
            }
        }
    }
    StopProgress();
}
//---------------------------------------------------------------------------
void __fastcall TAnalyzeThread::FindRTTIs()
{
    BYTE		paramCnt, numOps, methodKind, flags;
    WORD        dw, Count, methCnt;
    DWORD       dd, procSig;
    int			j, n, m, minValue, maxValue, elNum, pos, instrLen;
    ULONGLONG   baseTypeAdr, typInfo;
    PInfoRec    recN, recN1;
    String      name, unitName;
    DISINFO     DisInfo;

    int stepMask = StartProgress(TotalSize, "FindRTTIs");

    for (int i = 0; i < TotalSize && !Terminated; i += 8)
    {
        if ((i & stepMask) == 0) UpdateProgress();
        DWORD adr = *((DWORD*)(Code + i));
        if (IsValidImageAdr(adr) && adr == Pos2Adr(i) + 8)
        {
            //Euristica - look at byte Code + i - 3 - may be case (jmp [adr + reg*4])
            //instrLen = Disasm.Disassemble(Code + i - 3, (__int64)Pos2Adr(i) - 3, &DisInfo, 0);
            //if (instrLen > 3 && DisInfo.Branch && DisInfo.Offset == adr) continue;

        	DWORD typeAdr = adr - 8;
            BYTE typeKind = Code[i + 8];
            if (typeKind == ikUnknown || typeKind > ikProcedure) continue;

            BYTE len = Code[i + 9];
            if (!IsValidName(len, i + 10)) continue;

            String TypeName = GetTypeName(adr);
            UpdateStatusBar(TypeName);
            /*
            //Names that begins with '.'
            if (TypeName[1] == '.')
            {
                String prefix;
                switch (typeKind)
                {
                case ikEnumeration:
                    prefix = "_Enumeration_";
                    break;
                case ikArray:
                    prefix = "_Array_";
                    break;
                case ikDynArray:
                    prefix = "_DynArray_";
                    break;
                default:
                    prefix = form->GetUnitName(recU);
                    break;
                }
                TypeName = prefix + Val2Str0(recU->iniOrder) + "_" + TypeName.SubString(2, len);
            }
            */

            n = i + 10 + len;
            idr.SetFlag(cfRTTI, i);
            unitName = "";

            switch (typeKind)
            {
            case ikInteger:         //1
            case ikChar:            //2
            case ikWChar:           //9
            	n++;	//ordType
                n += 4;	//MinVal
                n += 4;	//MaxVal
                //AttrData
                dw = *((WORD*)(Code + n));
                n += dw;//ATR!!
                n = (n + 7) & (-8); //Align to 64-bit bound
                idr.SetFlags(cfData, i, n - i);
                break;
            case ikEnumeration:     //3
                n++;    //ordType
                minValue = *((int*)(Code + n)); n += 4;
                maxValue = *((int*)(Code + n)); n += 4;
                //BaseType
                baseTypeAdr = *((ULONGLONG*)(Code + n)); n += 8;

                if (baseTypeAdr == typeAdr)
                {
                    if (SameText(TypeName, "ByteBool") ||
                        SameText(TypeName, "WordBool") ||
                        SameText(TypeName, "LongBool"))
                    {
                        minValue = 0;
                        maxValue = 1;
                    }
                    for (j = minValue; j <= maxValue; j++)
                    {
                        len = Code[n];
                        n += len + 1;
                    }
                }
                //UnitName
                len = Code[n];
                if (IsValidName(len, n + 1))
                {
                    unitName = String((char*)(Code + n + 1), len).Trim();
                }
                 n += len + 1;
                //AttrData
                dw = *((WORD*)(Code + n)); n += dw;
                n = (n + 7) & (-8); //Align to 64-bit bound
                idr.SetFlags(cfData, i, n - i);
                break;
            case ikFloat:           //4
                n++;    //FloatType
                //AttrData
                dw = *((WORD*)(Code + n));
                n += dw;//ATR!!
                n = (n + 7) & (-8); //Align to 64-bit bound
                idr.SetFlags(cfData, i, n - i);
                break;
			case ikString:          //5
                n++;    //MaxLength
                //AttrData
                dw = *((WORD*)(Code + n));
                n += dw;//ATR!!
                n = (n + 7) & (-8); //Align to 64-bit bound
                idr.SetFlags(cfData, i, n - i);
                break;
            case ikSet:             //6
                n++;        //OrdType
                n += 8;     //CompType
                //AttrData
                dw = *((WORD*)(Code + n));
                n += dw;//ATR!!
                n = (n + 7) & (-8); //Align to 64-bit bound
                idr.SetFlags(cfData, i, n - i);
                break;
            case ikClass:           //7
                n += 8;     //classVMT
                n += 8;     //ParentInfo
                n += 2;     //PropCount
                //UnitName
                len = Code[n];
                if (IsValidName(len, n + 1))
                {
                    unitName = String((char*)(Code + n + 1), len).Trim();
                }
                n += len + 1;
                //PropData
                Count = *((WORD*)(Code + n)); n += 2;
                //PropList: array[1..PropCount] of TPropInfo
                for (j = 0; j < Count; j++)
                {
                    n += 0x2A;
                    len = Code[n]; n += len + 1;    //Name
                }
                //PropDataEx
                Count = *((WORD*)(Code + n)); n += 2;
                //PropList: array[1..PropCount] of TPropInfoEx
                for (j = 0; j < Count; j++)
                {
                    //TPropInfoEx
                    n++;    //Flags
                    //Info
                    typInfo = *((ULONGLONG*)(Code + n)); n += 8;
                    pos = Adr2Pos(typInfo);
                    len = Code[pos + 0x2A];
                    idr.SetFlags(cfData, pos, 0x2A + len);
                    //AttrData
                    dw = *((WORD*)(Code + n));
                    n += dw;//ATR!!
                }
                //AttrData
                dw = *((WORD*)(Code + n));
                n += dw;//ATR!!
                //ArrayPropCount
                Count = *((WORD*)(Code + n)); n += 2;
                //ArrayPropData
                for (j = 0; j < Count; j++)
                {
                    //Flags
                    n++;
                    //ReadIndex
                    n += 2;
                    //WriteIndex
                    n += 2;
                    //Name
                    len = Code[n]; n += len + 1;
                    //AttrData
                    dw = *((WORD*)(Code + n));
                    n += dw;//ATR!!
                }
                n = (n + 7) & (-8); //Align to 64-bit bound
                idr.SetFlags(cfData, i, n - i);
                break;
            case ikMethod:          //8
                //MethodKind
                methodKind = Code[n]; n++;  //0 (mkProcedure) or 1 (mkFunction)
                paramCnt = Code[n]; n++;
                for (j = 0; j < paramCnt; j++)
                {
                    n++;        //Flags
                    len = Code[n]; n += len + 1;    //ParamName
                    len = Code[n]; n += len + 1;    //TypeName
                }
                if (methodKind)
                {
                    //ResultType
                    len = Code[n]; n += len + 1;
                    //ResultTypeRef
                    n += 8;
                }
                //CC
                n++;
                //ParamTypeRefs
                n += 8 * paramCnt;
                //MethSig
                procSig = *((ULONGLONG*)(Code + n)); n += 8;
                //AttrData
                dw = *((WORD*)(Code + n));
                n += dw;//ATR!!
                //Procedure Signature
                if (procSig)
                {
                    if (IsValidImageAdr(procSig))
                        pos = Adr2Pos(procSig);
                    else
                        pos = i + procSig;
                    m = 0;
                    //Flags
                    flags = Code[pos]; m++;
                    if (flags != 0xFF)
                    {
                        //CC
                        m++;
                        //ResultType
                        m += 8;
                        //ParamCount
                        paramCnt = Code[pos + m]; m++;
                        for (j = 0; j < paramCnt; j++)
                        {
                            //Flags
                            m++;
                            //ParamType
                            m += 8;
                            //Name
                            len = Code[pos + m]; m += len + 1;
                            //AttrData
                            dw = *((WORD*)(Code + pos + m));
                            m += dw;//ATR!!
                        }
                    }
                    idr.SetFlags(cfData, pos, m);
                }
                n = (n + 7) & (-8); //Align to 64-bit bound
                idr.SetFlags(cfData, i, n - i);
                break;
            case ikLString:         //0xA
                n += 2;     //CodePage
                //AttrData
                dw = *((WORD*)(Code + n));
                n += dw;//ATR!!
                n = (n + 7) & (-8); //Align to 64-bit bound
                idr.SetFlags(cfData, i, n - i);
                break;
            case ikWString:         //0xB
                //AttrData
                dw = *((WORD*)(Code + n));
                n += dw;//ATR!!
                n = (n + 7) & (-8); //Align to 64-bit bound
                idr.SetFlags(cfData, i, n - i);
                break;
            case ikVariant:         //0xC
                //AttrData
                dw = *((WORD*)(Code + n));
                n += dw;//ATR!!
                n = (n + 7) & (-8); //Align to 64-bit bound
                idr.SetFlags(cfData, i, n - i);
                break;
            case ikArray:           //0xD
                n += 4;     //Size
                n += 4;     //ElCount
                n += 8;     //ElType
                //DimCount
                paramCnt = Code[n]; n++;
                for (j = 0; j < paramCnt; j++)
                {
                    //Dims: array[0..255 {DimCount-1}] of PPTypeInfo
                    n += 8;
                }
                //AttrData
                dw = *((WORD*)(Code + n));
                n += dw;//ATR!!
                n = (n + 7) & (-8); //Align to 64-bit bound
                idr.SetFlags(cfData, i, n - i);
                break;
            case ikRecord:          //0xE
                n += 4; //Size
                elNum = *((int*)(Code + n)); n += 4;    //ManagedFldCount
                for (j = 0; j < elNum; j++)             //ManagedFields: array[0..ManagedFldCnt - 1] of TManagedField
                {
                    n += 8; //TypeRef
                    n += 8; //FldOffset
                }
                numOps = Code[n]; n++;              //NumOps
                for (j = 0; j < numOps; j++)        //RecOps: array[1..NumOps] of Pointer
                {
                    n += 8;
                }
                elNum = *((int*)(Code + n)); n += 4;    //RecFldCnt
                for (j = 0; j < elNum; j++)         //RecFields: array[1..RecFldCnt] of TRecordTypeField
                {
                    n += 8; //TypeRef
                    n += 8; //FldOffset
                    n++;    //Flags
                    len = Code[n]; n += len + 1;    //Name
                    dw = *((WORD*)(Code + n));
                    if (dw != 2)
                        dummy = 1;
                    n += dw;//ATR!!
                }
                dw = *((WORD*)(Code + n));
                if (dw != 2)
                    dummy = 1;
                n += dw;//ATR!!
                methCnt = *((WORD*)(Code + n)); n += 2; //RecMethCnt
                for (j = 0; j < methCnt; j++)       //RecMeths: array[1..RecMethCnt] of TRecordTypeMethod
                {
                    n++;    //Flags
                    n += 8; //Code
                    len = Code[n]; n += len + 1;    //Name

                    //ProcedureSignature
                    flags = Code[n]; n++;           //Flags
                    if (flags != 0xFF)
                    {
                        //CC
                        n++;
                        //ResultType
                        n += 8;
                        //ParamCnt
                        paramCnt = Code[n]; n++;
                        for (m = 0; m < paramCnt; m++)  //Params: array[1..ParamCount] of TProcedureParam
                        {
                            n++;    //Flags
                            n += 8; //ParamType
                            len = Code[n]; n += len + 1;    //Name
                            dw = *((WORD*)(Code + n));
                            if (dw != 2)
                                dummy = 1;
                            n += dw;//ATR!!
                        }
                    }
                    dw = *((WORD*)(Code + n));
                    if (dw != 2)
                        dummy = 1;
                    n += dw;//ATR!!
                }
                n = (n + 7) & (-8); //Align to 64-bit bound
                idr.SetFlags(cfData, i, n - i);
                break;
            case ikInterface:       //0xF
                n += 8;     //IntfParent
                n++;        //IntfFlags
                n += 16;    //GUID
                //UnitName
                len = Code[n];
                if (IsValidName(len, n + 1))
                {
                    unitName = String((char*)(Code + n + 1), len).Trim();
                }
                n += len + 1;
                //IntfMethods: TIntfMethodTable
                //PropCount
                Count = *((WORD*)(Code + n)); n += 2;
                //RttiCount
                dw = *((WORD*)(Code + n)); n += 2;
                if (dw != 0xFFFF)
                {
                    //Entry: array[1..Count] of TIntfMethodEntry
                    for (j = 0; j < Count; j++)
                    {
                        //Name
                        len = Code[n]; n += len + 1;
                        //Kind
                        methodKind = Code[n]; n++;
                        //CallConv
                        n++;
                        //ParamCount
                        paramCnt = Code[n]; n++;
                        //Params: array[1..ParamCount] of TIntfMethodParam
                        for (m = 0; m < paramCnt; m++)
                        {
                            //Flags
                            n++;
                            //ParamName
                            len = Code[n]; n += len + 1;
                            //TypeName
                            len = Code[n]; n += len + 1;
                            //Tail
                            //ParamType
                            n += 8;
                            //AttrData
                            dw = *((WORD*)(Code + n));
                            n += dw;//ATR!!
                        }
                        if (methodKind)
                        {
                            //ResultTypeName
                            len = Code[n]; n += len + 1;
                            if (len)
                            {
                                //ResultType
                                n += 8;
                                //AttrData
                                dw = *((WORD*)(Code + n));
                                n += dw;//ATR!!
                            }
                        }
                    }
                }
                //AttrData
                dw = *((WORD*)(Code + n));
                n += dw;//ATR!!
                n = (n + 7) & (-8); //Align to 64-bit bound
                idr.SetFlags(cfData, i, n - i);
                break;
            case ikInt64:           //0x10
                n += 8;     //MinVal
                n += 8;     //MaxVal
                //AttrData
                dw = *((WORD*)(Code + n));
                n += dw;//ATR!!
                n = (n + 7) & (-8); //Align to 64-bit bound
                idr.SetFlags(cfData, i, n - i);
                break;
            case ikDynArray:        //0x11
                n += 4;     //elSize
                n += 8;     //elType
                n += 8;     //varType
                n += 8;     //elType2
                //UnitName
                len = Code[n];
                if (IsValidName(len, n + 1))
                {
                    unitName = String((char*)(Code + n + 1), len).Trim();
                }
                 n += len + 1;
                //DynArrElType
                n += 8;
                //AttrData
                dw = *((WORD*)(Code + n));
                n += dw;//ATR!!
                n = (n + 7) & (-8); //Align to 64-bit bound
                idr.SetFlags(cfData, i, n - i);
                break;
            case ikUString:         //0x12
                //AttrData
                dw = *((WORD*)(Code + n));
                n += dw;//ATR!!
                n = (n + 7) & (-8); //Align to 64-bit bound
                idr.SetFlags(cfData, i, n - i);
                break;
            case ikClassRef:        //0x13
                //InstanceType
                n += 8;
                //AttrData
                dw = *((WORD*)(Code + n));
                n += dw;//ATR!!
                n = (n + 7) & (-8); //Align to 64-bit bound
                idr.SetFlags(cfData, i, n - i);
            	break;
            case ikPointer:         //0x14
                //RefType
                n += 8;
                //AttrData
                dw = *((WORD*)(Code + n));
                n += dw;//ATR!!
                n = (n + 7) & (-8); //Align to 64-bit bound
                idr.SetFlags(cfData, i, n - i);
            	break;
            case ikProcedure:       //0x15
                //MethSig
                procSig = *((DWORD*)(Code + n)); n += 8;
                //AttrData
                dw = *((WORD*)(Code + n));
                n += dw;//ATR!!
                n = (n + 7) & (-8); //Align to 64-bit bound
                idr.SetFlags(cfData, i, n - i);
                //Procedure Signature
                if (procSig)
                {
                    if (IsValidImageAdr(procSig))
                        pos = Adr2Pos(procSig);
                    else
                        pos = i + procSig;
                    m = 0;
                    //Flags
                    flags = Code[pos]; m++;
                    if (flags != 0xFF)
                    {
                        //CC
                        m++;
                        //ResultType
                        m += 8;
                        //ParamCount
                        paramCnt = Code[pos + m]; m++;
                        //Params: array[1..ParamCount] of TProcedureParam
                        for (j = 0; j < paramCnt; j++)
                        {
                            //Flags
                            m++;
                            //ParamType
                            m += 8;
                            //Name
                            len = Code[pos + m]; m += len + 1;
                            //AttrData
                            dw = *((WORD*)(Code + pos + m));
                            m += dw;//ATR!!
                        }
                    }
                    idr.SetFlags(cfData, pos, m);
                }
            	break;
            }

            if (!idr.HasInfosAt(i))
            {
            	recN = new InfoRec(i, typeKind);
	            recN->SetName(TypeName);
            }
            PTypeRec recT = new TypeRec;
            recT->kind = typeKind;
            recT->adr = typeAdr;
            if (unitName != "") TypeName += " (" + unitName + ")";
            recT->name = TypeName;
            OwnTypeList->Add(recT);
        }
	}
    StopProgress();
}
//---------------------------------------------------------------------------
int __fastcall TAnalyzeThread::CheckAdjustment(int Adjustment)
{
    WORD    Num16;
    int     pos, EntryCount, VMTCount = 0;
    DWORD   Num32;

    for (int i = 0; i < TotalSize && !Terminated; i += 8)
    {
        if (idr.IsFlagSet(cfCode | cfData, i)) continue;
        DWORD adr = *((ULONGLONG*)(Code + i));  //Points to vmt0 (VmtSelfPtr)
        if (IsValidImageAdr(adr) && Pos2Adr(i) == adr + Vmt.SelfPtr + Adjustment)
        {
            DWORD intfTableAdr = *((ULONGLONG*)(Code + i + 8));
            if (intfTableAdr)
            {
                if (!IsValidImageAdr(intfTableAdr)) continue;
                pos = Adr2Pos(intfTableAdr);
                EntryCount = *((ULONGLONG*)(Code + pos));
                if (EntryCount > 10000) continue;
            }
            DWORD autoTableAdr = *((ULONGLONG*)(Code + i + 0x10));
            if (autoTableAdr)
            {
                if (!IsValidImageAdr(autoTableAdr)) continue;
                pos = Adr2Pos(autoTableAdr);
                EntryCount = *((DWORD*)(Code + pos));
                if (EntryCount > 10000) continue;
            }
            DWORD initTableAdr = *((ULONGLONG*)(Code + i + 0x18));
            if (initTableAdr)
            {
                if (!IsValidImageAdr(initTableAdr)) continue;
                pos = Adr2Pos(initTableAdr);
                Num32 = *((DWORD*)(Code + pos + 6));
                if (Num32 > 10000) continue;
            }
            DWORD typeInfoAdr = *((ULONGLONG*)(Code + i + 0x20));
            if (typeInfoAdr)
            {
                if (!IsValidImageAdr(typeInfoAdr)) continue;
                pos = Adr2Pos(typeInfoAdr);
                BYTE typeKind = *(Code + pos);
                if (typeKind > ikProcedure) continue;
            }

            DWORD fieldTableAdr = *((ULONGLONG*)(Code + i + 0x28));
            if (fieldTableAdr)
            {
                if (!IsValidImageAdr(fieldTableAdr)) continue;
                pos = Adr2Pos(fieldTableAdr);
                Num16 = *((WORD*)(Code + pos));
                if (Num16 > 10000) continue;
            }

            DWORD methodTableAdr = *((ULONGLONG*)(Code + i + 0x30));
            if (methodTableAdr)
            {
                if (!IsValidImageAdr(methodTableAdr)) continue;
                pos = Adr2Pos(methodTableAdr);
                Num16 = *((WORD*)(Code + pos));
                if (Num16 > 10000) continue;
            }

            DWORD dynamicTableAdr = *((ULONGLONG*)(Code + i + 0x38));
            if (dynamicTableAdr)
            {
                if (!IsValidImageAdr(dynamicTableAdr)) continue;
                pos = Adr2Pos(dynamicTableAdr);
                Num16 = *((WORD*)(Code + pos));
                if (Num16 > 10000) continue;
            }

            DWORD classNameAdr = *((ULONGLONG*)(Code + i + 0x40));
            if (!classNameAdr || !IsValidImageAdr(classNameAdr)) continue;

            DWORD parentAdr = *((ULONGLONG*)(Code + i + 0x50));
            if (parentAdr && !IsValidImageAdr(parentAdr)) continue;

            VMTCount++;
        }
    }
    return VMTCount;
}
//---------------------------------------------------------------------------
//Collect information from VMT structure
void __fastcall TAnalyzeThread::FindVMTs()
{
    WORD    Num16;
    int     bytes, pos, posv, EntryCount, Adjustment;
    DWORD   Num32;

    int stepMask = StartProgress(TotalSize, "FindVMTs");
    int Adj0Count = CheckAdjustment(0);
    int Adj24Count = CheckAdjustment(-24);

    if (Adj0Count > Adj24Count)
        Adjustment = 0;
    else
    {
        Adjustment = -24;
        Vmt.AdjustVmtConsts(Adjustment);
    }

    for (int i = 0; i < TotalSize && !Terminated; i += 8)
    {
        if ((i & stepMask) == 0) UpdateProgress();
        if (idr.IsFlagSet(cfCode | cfData, i)) continue;
        DWORD adr = *((ULONGLONG*)(Code + i));  //Points to vmt0 (VmtSelfPtr)
        if (IsValidImageAdr(adr) && Pos2Adr(i) == adr + Vmt.SelfPtr)
        {
            DWORD classVMT = adr;
            DWORD StopAt = GetStopAt(classVMT);
            //if (i + StopAt - classVMT - VmtSelfPtr >= CodeSize) continue;

            DWORD intfTableAdr = *((ULONGLONG*)(Code + i + 8));
            if (intfTableAdr)
            {
                if (!IsValidImageAdr(intfTableAdr)) continue;
                pos = Adr2Pos(intfTableAdr);
                EntryCount = *((ULONGLONG*)(Code + pos));
                if (EntryCount > 10000) continue;
            }

            DWORD autoTableAdr = *((ULONGLONG*)(Code + i + 0x10));
            if (autoTableAdr)
            {
                if (!IsValidImageAdr(autoTableAdr)) continue;
                pos = Adr2Pos(autoTableAdr);
                EntryCount = *((DWORD*)(Code + pos));
                if (EntryCount > 10000) continue;
            }

            DWORD initTableAdr = *((ULONGLONG*)(Code + i + 0x18));
            if (initTableAdr)
            {
                if (!IsValidImageAdr(initTableAdr)) continue;
                pos = Adr2Pos(initTableAdr);
                Num32 = *((DWORD*)(Code + pos + 6));
                if (Num32 > 10000) continue;
            }

            DWORD typeInfoAdr = *((ULONGLONG*)(Code + i + 0x20));
            if (typeInfoAdr)
            {
                if (!IsValidImageAdr(typeInfoAdr)) continue;
                //Address typeInfoAdr must contain data about type, that begin with typeKind
                pos = Adr2Pos(typeInfoAdr);
                BYTE typeKind = *(Code + pos);
                if (typeKind > ikProcedure) continue;
                //len = *(Code + pos + 1);
                //if (!IsValidName(len, pos + 2)) continue;
            }

            DWORD fieldTableAdr = *((ULONGLONG*)(Code + i + 0x28));
            if (fieldTableAdr)
            {
                if (!IsValidImageAdr(fieldTableAdr)) continue;
                pos = Adr2Pos(fieldTableAdr);
                Num16 = *((WORD*)(Code + pos));
                if (Num16 > 10000) continue;
            }

            DWORD methodTableAdr = *((ULONGLONG*)(Code + i + 0x30));
            if (methodTableAdr)
            {
                if (!IsValidImageAdr(methodTableAdr)) continue;
                pos = Adr2Pos(methodTableAdr);
                Num16 = *((WORD*)(Code + pos));
                if (Num16 > 10000) continue;
            }

            DWORD dynamicTableAdr = *((ULONGLONG*)(Code + i + 0x38));
            if (dynamicTableAdr)
            {
                if (!IsValidImageAdr(dynamicTableAdr)) continue;
                pos = Adr2Pos(dynamicTableAdr);
                Num16 = *((WORD*)(Code + pos));
                if (Num16 > 10000) continue;
            }

            DWORD classNameAdr = *((ULONGLONG*)(Code + i + 0x40));
            if (!classNameAdr || !IsValidImageAdr(classNameAdr)) continue;

            //n = Adr2Pos(classNameAdr);
            //len = *(Code + n);
            //if (!IsValidName(len, n + 1)) continue;

            DWORD parentAdr = *((ULONGLONG*)(Code + i + 0x50));
            if (parentAdr && !IsValidImageAdr(parentAdr)) continue;

            int pos1 = Adr2Pos(classNameAdr);
            BYTE len = Code[pos1];
            //if (!IsValidName(len, pos1 + 1)) continue;
            String TypeName = String((char*)(Code + pos1 + 1), len);
            UpdateStatusBar(TypeName);
            
            //Add to TypeList
            PTypeRec recT = new TypeRec;
            recT->kind = ikVMT;
            recT->adr = Pos2Adr(i);
            recT->name = TypeName;
            OwnTypeList->Add(recT);

            //Name already use
            idr.SetFlags(cfData, pos1, len + 1);

            if (!GetInfoRec(Pos2Adr(i)))
            {
                PInfoRec recN = new InfoRec(i, ikVMT);
                recN->SetName(TypeName);
            }
            idr.SetFlag(cfData, i);

            //IntfTable
            DWORD vTableAdr;

            if (intfTableAdr)
            {
                pos = Adr2Pos(intfTableAdr); bytes = 0;
                idr.SetFlag(cfData | cfVTable, pos);
                EntryCount = *((ULONGLONG*)(Code + pos)); pos += 8; bytes += 8;
                for (int m = 0; m < EntryCount; m++)
                {
                    //GUID
                    pos += 16; bytes += 16;
                    vTableAdr = *((ULONGLONG*)(Code + pos)); pos += 8; bytes += 8;
                    if (IsValidImageAdr(vTableAdr)) idr.SetFlag(cfData | cfVTable, Adr2Pos(vTableAdr));
                    //IOffset
                    pos += 8; bytes += 8;
                    //ImplGetter
                    pos += 8; bytes += 8;
                }
                //Intfs
                bytes += EntryCount * 8;

                //Use IntfTable
                idr.SetFlags(cfData, Adr2Pos(intfTableAdr), bytes);
                //Second pass (to use already set flags)
                pos = Adr2Pos(intfTableAdr) + 8;
                for (int m = 0; m < EntryCount; m++)
                {
                    //Skip GUID
                    pos += 16;
                    vTableAdr = *((ULONGLONG*)(Code + pos)); pos += 8;
                    //IOffset
                    pos += 8;
                    //ImplGetter
                    pos += 8;
                    //Use VTable
                    if (IsValidImageAdr(vTableAdr))
                    {
                        DWORD vEnd = vTableAdr;
                        DWORD vStart = vTableAdr;
                        posv = Adr2Pos(vTableAdr); bytes = 0;
                        for (int k = 0;; k++)
                        {
                            if (Pos2Adr(posv) == intfTableAdr) break;
                            DWORD vAdr = *((ULONGLONG*)(Code + posv)); posv += 8; bytes += 8;
                            if (vAdr && vAdr < vStart) vStart = vAdr;
                        }
                        //Use VTable
                        idr.SetFlags(cfData, Adr2Pos(vEnd), bytes);
                        //Leading always byte CC
                        vStart--;
                        //Use all refs
                        idr.SetFlags(cfData, Adr2Pos(vStart), vEnd - vStart);
                    }
                }
            }
            //AutoTable
            if (autoTableAdr)
            {
                pos = Adr2Pos(autoTableAdr); bytes = 0;
                EntryCount = *((DWORD*)(Code + pos)); pos += 4; bytes += 4;
                for (int m = 0; m < EntryCount; m++)
                {
                    //DispID: LongInt
                    pos += 4; bytes += 4;
                    //Name: PShortString
                    DWORD pos1 = Adr2Pos(*((ULONGLONG*)(Code + pos))); pos += 8; bytes += 8;
                    len = Code[pos1];
                    //Use name
                    idr.SetFlags(cfData, pos1, len + 1);
                    //Flags: LongInt; { Lower byte contains flags }
                    pos += 4; bytes += 4;
                    //Params: PAutoParamList
                    pos1 = Adr2Pos(*((ULONGLONG*)(Code + pos))); pos += 8; bytes += 8;
                    BYTE ParamCnt = Code[pos1 + 1];
                    //Use Params
                    idr.SetFlags(cfData, pos1, ParamCnt + 2);
                    //Address: Pointer
                    pos += 8; bytes += 8;
                }
                //Use AutoTable
                idr.SetFlags(cfData, Adr2Pos(autoTableAdr), bytes);
            }
            //InitTable
            if (initTableAdr)
            {
                pos = Adr2Pos(initTableAdr); bytes = 0;
                //Skip 0xE
                pos++; bytes++;
                //Unknown byte
                pos++; bytes++;
                //Unknown dword
                pos += 4; bytes += 4;
                Num32 = *((DWORD*)(Code + pos)); bytes += 4;

                for (int m = 0; m < Num32; m++)
                {
                    //TypeOfs (information about types is already extracted)
                    bytes += 8;
                    //FieldOfs
                    bytes += 8;
                }
                //Use InitTable
                idr.SetFlags(cfData, Adr2Pos(initTableAdr), bytes);
            }
            //FieldTable
            if (fieldTableAdr)
            {
                pos = Adr2Pos(fieldTableAdr); bytes = 0;
                Num16 = *((WORD*)(Code + pos)); pos += 2; bytes += 2;
                //TypesTab
                DWORD typesTab = *((ULONGLONG*)(Code + pos)); pos += 8; bytes += 8;

                for (int m = 0; m < Num16; m++)
                {
                    //Offset
                    pos += 4; bytes += 4;
                    //Idx
                    pos += 2; bytes += 2;
                    //Name
                    len = Code[pos]; pos++; bytes++;
                    pos += len; bytes += len;
                }
                //Use TypesTab
                if (typesTab)
                {
                    Num16 = *((WORD*)(Code + Adr2Pos(typesTab)));
                    idr.SetFlags(cfData, Adr2Pos(typesTab), 2 + Num16*8);
                }
                //Extended Information
                Num16 = *((WORD*)(Code + pos)); pos += 2; bytes += 2;
                for (int m = 0; m < Num16; m++)
                {
                    //Flags
                    pos++; bytes++;
                    //TypeRef
                    pos += 8; bytes += 8;
                    //Offset
                    pos += 4; bytes += 4;
                    //Name
                    len = Code[pos]; pos++; bytes++;
                    pos += len; bytes += len;
                    //AttrData
                    WORD dw = *((WORD*)(Code + pos));
                    pos += dw; bytes += dw;//ATR!!
                }
                //Use FieldTable
                idr.SetFlags(cfData, Adr2Pos(fieldTableAdr), bytes);
            }
            //MethodTable
            if (methodTableAdr)
            {
                pos = Adr2Pos(methodTableAdr); bytes = 0;
                Num16 = *((WORD*)(Code + pos)); pos += 2; bytes += 2;

                for (int m = 0; m < Num16; m++)
                {
                    //Len
                    WORD skipBytes = *((WORD*)(Code + pos)); pos += skipBytes; bytes += skipBytes;
                }
                Num16 = *((WORD*)(Code + pos)); pos += 2; bytes += 2;
                for (int m = 0; m < Num16; m++)
                {
                    //MethodEntry
                    ULONGLONG methodEntry = *((ULONGLONG*)(Code + pos)); pos += 8; bytes += 8;
                    WORD skipBytes = *((WORD*)(Code + Adr2Pos(methodEntry)));
                    idr.SetFlags(cfData, Adr2Pos(methodEntry), skipBytes);
                    //SkipBytes
                    pos += 2; bytes += 2;
                    //VirtualIndex
                    pos += 2; bytes += 2;
                }
                //VirtCount
                bytes += 2;
                //Use MethodTable
                idr.SetFlags(cfData, Adr2Pos(methodTableAdr), bytes);
            }
            //DynamicTable
            if (dynamicTableAdr)
            {
                pos = Adr2Pos(dynamicTableAdr); bytes = 0;
                Num16 = *((WORD*)(Code + pos)); bytes += 2;
                for (int m = 0; m < Num16; m++)
                {
                    //Msg+ProcAdr
                    bytes += 10;
                }
                //Use DynamicTable
                idr.SetFlags(cfData, Adr2Pos(dynamicTableAdr), bytes);
            }

            //DWORD StopAt = GetStopAt(classVMT);
            //Use Virtual Table
            idr.SetFlags(cfData, i, StopAt - classVMT - Vmt.SelfPtr);
            PUnitRec recU = GetUnit(classVMT);
            if (recU)
            {
                adr = *((DWORD*)(Code + i - Vmt.SelfPtr + Vmt.TypeInfo));
                if (adr && IsValidImageAdr(adr))
                {
                    //Extract unit name
                    pos = Adr2Pos(adr); bytes = 0;
                    BYTE b = Code[pos]; pos++; bytes++;
                    if (b != 7) continue;
                    len = Code[pos]; pos++; bytes++;
                    if (!IsValidName(len, pos)) continue;
                    pos += len + 2 * 8 + 2; bytes += len + 2 * 8 + 2;
                    len = Code[pos]; pos++; bytes++;
                    if (!IsValidName(len, pos)) continue;
                    String unitName = String((char*)(Code + pos), len).Trim(); bytes += len;
                    SetUnitName(recU, unitName);
                    //Use information about Unit
                    idr.SetFlags(cfData, Adr2Pos(adr), bytes);
                }
            }
        }
    }
    StopProgress();
}
//---------------------------------------------------------------------------
void __fastcall TAnalyzeThread::StrapVMTs()
{
    int stepMask = StartProgress(TotalSize, "StrapVMTs");

    MConstInfo cInfo;
    for (int i = 0; i < TotalSize && !Terminated; i += 8)
    {
        if ((i & stepMask) == 0) UpdateProgress();
        PInfoRec recN = GetInfoRec(Pos2Adr(i));
    	if (recN && recN->kind == ikVMT)
        {
            String _name = recN->GetName();
            String ConstName = "_DV_" + _name;
            WORD *uses = KnowledgeBase.GetConstUses(ConstName.c_str());
            int ConstIdx = KnowledgeBase.GetConstIdx(uses, ConstName.c_str());
            if (ConstIdx != -1)
            {
                ConstIdx = KnowledgeBase.ConstOffsets[ConstIdx].NamId;
                if (KnowledgeBase.GetConstInfo(ConstIdx, INFO_DUMP, &cInfo))
                {
                    UpdateStatusBar(_name);
                    StrapVMT(i, ConstIdx, &cInfo);
                }
            }
            if (uses) delete[] uses;
        }
    }
    StopProgress();
}
//---------------------------------------------------------------------------
void __fastcall TAnalyzeThread::FindTypeFields()
{
    int     typeSize;
    int     stepMask = StartProgress(TotalSize, "FindTypeFields");

    MTypeInfo   atInfo;
    MTypeInfo   *tInfo = &atInfo;

    for (int i = 0; i < TotalSize && !Terminated; i += 8)
    {
        if ((i & stepMask) == 0) UpdateProgress();
        PInfoRec recN = GetInfoRec(Pos2Adr(i));
    	if (recN && recN->kind == ikVMT)
        {
            DWORD vmtAdr = Pos2Adr(i) - Vmt.SelfPtr;
            PUnitRec recU = GetUnit(vmtAdr);
            if (recU)
            {
                for (int u = 0; u < recU->names->Count && !Terminated; u++)
                {
                    WORD ModuleID = KnowledgeBase.GetModuleID(recU->names->Strings[u].c_str());
                    WORD *uses = KnowledgeBase.GetModuleUses(ModuleID);
                    //Find Type to extract information about fields
                    int TypeIdx = KnowledgeBase.GetTypeIdxByModuleIds(uses, recN->GetName().c_str());
                    if (TypeIdx != -1)
                    {
                        TypeIdx = KnowledgeBase.TypeOffsets[TypeIdx].NamId;
                        if(KnowledgeBase.GetTypeInfo(TypeIdx, INFO_FIELDS, tInfo))
                        {
                            if (tInfo->Fields)
                            {
                                UpdateStatusBar(tInfo->TypeName);
                                BYTE *p = tInfo->Fields;
                                FIELDINFO fInfo;
                                for (int n = 0; n < tInfo->FieldsNum; n++)
                                {
                                    fInfo.Scope = *p; p++;
                                    fInfo.Offset = *((int*)p); p += 4;
                                    fInfo.Case = *((int*)p); p += 4;
                                    WORD Len = *((WORD*)p); p += 2;
                                    fInfo.Name = String((char*)p, Len); p += Len + 1;
                                    Len = *((WORD*)p); p += 2;
                                    fInfo.Type = TrimTypeName(String((char*)p, Len)); p += Len + 1;
                                    recN->vmtInfo->AddField(0, 0, fInfo.Scope, fInfo.Offset, fInfo.Case, fInfo.Name, fInfo.Type);
                                }
                            }
                        }
                    }
                    if (uses) delete[] uses;
                }
            }
        }
    }
    StopProgress();

    const int cntVmt = VmtList->Count;
    stepMask = StartProgress(cntVmt, "Propagate VMT Names");
    for (int n = 0; n < cntVmt && !Terminated; n++)
    {
        if ((n & stepMask) == 0) UpdateProgress();
        PVmtListRec recV = (PVmtListRec)VmtList->Items[n];
        UpdateStatusBar(GetClsName(recV->vmtAdr));
        PropagateVMTNames(recV->vmtAdr);
    }
    StopProgress();
}
//---------------------------------------------------------------------------
String __fastcall TAnalyzeThread::FindEvent(DWORD VmtAdr, String Name)
{
    DWORD adr = VmtAdr;
    while (adr)
    {
        PInfoRec recN = GetInfoRec(adr);
        if (recN && recN->vmtInfo->fields)
        {
            for (int n = 0; n < recN->vmtInfo->fields->Count; n++)
            {
                PFIELDINFO fInfo = (PFIELDINFO)recN->vmtInfo->fields->Items[n];
                if (SameText(fInfo->Name, Name)) return fInfo->Type;
            }
        }
        adr = GetParentAdr(adr);
    }
    return "";
}
//---------------------------------------------------------------------------
void __fastcall TAnalyzeThread::FindPrototypes()
{
    int         n, m, k, r, idx, usesNum;
    PInfoRec    recN;
    String      importName, _name;
    MProcInfo   aInfo;
    MProcInfo   *pInfo = &aInfo;
    MTypeInfo   atInfo;
    MTypeInfo   *tInfo = &atInfo;
    WORD        uses[128];

    int stepMask = StartProgress(TotalSize, "Find Import Prototypes");

    for (n = 0; n < TotalSize && !Terminated; n += 8)
    {
        if ((n & stepMask) == 0) UpdateProgress();
        if (idr.IsFlagSet(cfImport, n))
        {
            recN = GetInfoRec(Pos2Adr(n));
            _name = recN->GetName();
            int dot = _name.Pos(".");
            int len = _name.Length();
            bool found = false;
            BYTE *p; WORD wlen;
            //try find arguments
            //FullName
            importName = _name.SubString(dot + 1, len);
            usesNum = KnowledgeBase.GetProcUses(importName.c_str(), uses);
            for (m = 0; m < usesNum && !Terminated; m++)
            {
                idx = KnowledgeBase.GetProcIdx(uses[m], importName.c_str());
                if (idx != -1)
                {
                    idx = KnowledgeBase.ProcOffsets[idx].NamId;
                    if (KnowledgeBase.GetProcInfo(idx, INFO_ARGS, pInfo))
                    {
                        if (pInfo->MethodKind == 'F')
                        {
                            recN->kind = ikFunc;
                            recN->type = pInfo->TypeDef;
                        }
                        else if (pInfo->MethodKind == 'P')
                        {
                            recN->kind = ikProc;
                        }
                        if (!recN->procInfo)
                            recN->procInfo = new InfoProcInfo;

                        if (pInfo->Args)
                        {
                            BYTE callKind = pInfo->CallKind;

                            recN->procInfo->flags |= callKind;

                            ARGINFO argInfo; p = pInfo->Args; int ss = 8;
                            for (k = 0; k < pInfo->ArgsNum; k++)
                            {
                                FillArgInfo(k, callKind, &argInfo, &p, &ss);
                                recN->procInfo->AddArg(&argInfo);
                            }
                            found = true;
                        }
                    }
                    if (found) break;
                }
            }
            if (!found)
            {
                //try short name
                importName = _name.SubString(dot + 1, len - dot - 1);
                usesNum = KnowledgeBase.GetProcUses(importName.c_str(), uses);
                for (m = 0; m < usesNum && !Terminated; m++)
                {
                    idx = KnowledgeBase.GetProcIdx(uses[m], importName.c_str());
                    if (idx != -1)
                    {
                        idx = KnowledgeBase.ProcOffsets[idx].NamId;
                        if (KnowledgeBase.GetProcInfo(idx, INFO_ARGS, pInfo))
                        {
                            if (pInfo->MethodKind == 'F')
                            {
                                recN->kind = ikFunc;
                                recN->type = pInfo->TypeDef;
                            }
                            else if (pInfo->MethodKind == 'P')
                            {
                                recN->kind = ikProc;
                            }
                            if (!recN->procInfo)
                                recN->procInfo = new InfoProcInfo;

                            if (pInfo->Args)
                            {
                                BYTE callKind = pInfo->CallKind;
                                recN->procInfo->flags |= callKind;

                                ARGINFO argInfo; p = pInfo->Args; int ss = 8;
                                for (k = 0; k < pInfo->ArgsNum; k++)
                                {
                                    FillArgInfo(k, callKind, &argInfo, &p, &ss);
                                    recN->procInfo->AddArg(&argInfo);
                                }
                                found = true;
                            }
                        }
                        if (found) break;
                    }
                }
            }
            if (!found)
            {
                //try without arguments
                //FullName
                importName = _name.SubString(dot + 1, len - dot);
                usesNum = KnowledgeBase.GetProcUses(importName.c_str(), uses);
                for (m = 0; m < usesNum && !Terminated; m++)
                {
                    idx = KnowledgeBase.GetProcIdx(uses[m], importName.c_str());
                    if (idx != -1)
                    {
                        idx = KnowledgeBase.ProcOffsets[idx].NamId;
                        if (KnowledgeBase.GetProcInfo(idx, INFO_ARGS, pInfo))
                        {
                            if (pInfo->MethodKind == 'F')
                            {
                                recN->kind = ikFunc;
                                recN->type = pInfo->TypeDef;
                            }
                            else if (pInfo->MethodKind == 'P')
                            {
                                recN->kind = ikProc;
                            }
                            found = true;
                        }
                        if (found) break;
                    }
                }
            }
            if (!found)
            {
                //try without arguments
                //ShortName
                importName = _name.SubString(dot + 1, len - dot - 1);
                usesNum = KnowledgeBase.GetProcUses(importName.c_str(), uses);
                for (m = 0; m < usesNum && !Terminated; m++)
                {
                    idx = KnowledgeBase.GetProcIdx(uses[m], importName.c_str());
                    if (idx != -1)
                    {
                        idx = KnowledgeBase.ProcOffsets[idx].NamId;
                        if (KnowledgeBase.GetProcInfo(idx, INFO_ARGS, pInfo))
                        {
                            if (pInfo->MethodKind == 'F')
                            {
                                recN->kind = ikFunc;
                                recN->type = pInfo->TypeDef;
                            }
                            else if (pInfo->MethodKind == 'P')
                            {
                                recN->kind = ikProc;
                            }
                            found = true;
                        }
                        if (found) break;
                    }
                }
            }
        }
    }
    StopProgress();

    StartProgress(idr.ResInfo()->GetDfmCount(), "Find Event Prototypes");

    for (n = 0; n < idr.ResInfo()->GetDfmCount() && !Terminated; n++)
    {
        UpdateProgress();
        TDfm* dfm = idr.ResInfo()->GetDfm(n);
        String className = dfm->ClassName;
        DWORD formAdr = GetClassAdr(className);
        if (!formAdr) continue;
        recN = GetInfoRec(formAdr);
        if (!recN || !recN->vmtInfo->methods) continue;

        //The first: form events
        TList* ev = dfm->Events;
        for (m = 0; m < ev->Count && !Terminated; m++)
        {
            PEventInfo eInfo = (PEventInfo)ev->Items[m];
            DWORD controlAdr = GetClassAdr(dfm->ClassName);
            String typeName = FindEvent(controlAdr, "F" + eInfo->EventName);
            if (typeName == "") typeName = FindEvent(controlAdr, eInfo->EventName);
            if (typeName != "")
            {
                for (k = 0; k < recN->vmtInfo->methods->Count && !Terminated; k++)
                {
                    PMethodRec recM = (PMethodRec)recN->vmtInfo->methods->Items[k];
                    if (SameText(recM->name, className + "." + eInfo->ProcName))
                    {
                        PInfoRec recN1 = GetInfoRec(recM->address);
                        if (recN1)
                        {
                            String clsname = className;
                            while (1)
                            {
                                if (KnowledgeBase.GetKBPropertyInfo(clsname, eInfo->EventName, tInfo))
                                {
                                    recN1->kind = ikProc;
                                    recN1->procInfo->flags |= PF_EVENT;
                                    recN1->procInfo->DeleteArgs();
                                    //eax always Self
                                    recN1->procInfo->AddArg(0x21, 0, 4, "Self", className);
                                    //transform declaration to arguments
                                    recN1->procInfo->AddArgsFromDeclaration(tInfo->Decl.c_str(), 1, 0);
                                    break;
                                }
                                clsname = GetParentName(clsname);
                                if (clsname == "") break;
                            }
                        }
                        else
                        {
                            ShowMessage("recN is Null");
                        }
                        break;
                    }
                }
            }
        }
        //The second: components events
        for (m = 0; m < dfm->Components->Count && !Terminated; m++)
        {
            PComponentInfo cInfo = (PComponentInfo)dfm->Components->Items[m];
            TList* ev = cInfo->Events;
            for (k = 0; k < ev->Count && !Terminated; k++)
            {
                PEventInfo eInfo = (PEventInfo)ev->Items[k];
                DWORD controlAdr = GetClassAdr(cInfo->ClassName);
                String typeName = FindEvent(controlAdr, "F" + eInfo->EventName);
                if (typeName == "") typeName = FindEvent(controlAdr, eInfo->EventName);
                if (typeName != "")
                {
                    for (r = 0; r < recN->vmtInfo->methods->Count && !Terminated; r++)
                    {
                        PMethodRec recM = (PMethodRec)recN->vmtInfo->methods->Items[r];
                        if (SameText(recM->name, className + "." + eInfo->ProcName))
                        {
                            PInfoRec recN1 = GetInfoRec(recM->address);
                            if (recN1)
                            {
                                String clsname = className;
                                while (1)
                                {
                                    if (KnowledgeBase.GetKBPropertyInfo(clsname, eInfo->EventName, tInfo))
                                    {
                                        recN1->kind = ikProc;
                                        recN1->procInfo->flags |= PF_EVENT;
                                        recN1->procInfo->DeleteArgs();
                                        //eax always Self
                                        recN1->procInfo->AddArg(0x21, 0, 4, "Self", className);
                                        //transform declaration to arguments
                                        recN1->procInfo->AddArgsFromDeclaration(tInfo->Decl.c_str(), 1, 0);
                                        break;
                                    }
                                    clsname = GetParentName(clsname);
                                    if (clsname == "") break;
                                }
                            }
                            else
                            {
                                ShowMessage("recN is Null");
                            }
                            break;
                        }
                    }
                }
            }
        }
    }
    StopProgress();
}
//---------------------------------------------------------------------------
void __fastcall TAnalyzeThread::ScanCode()
{
    bool        matched;
    WORD        moduleID;
    DWORD       Adr, iniAdr, finAdr, vmtAdr;
    int         FirstProcIdx, LastProcIdx, Num;
    int         i, n, m, k, r, u, Idx, fromPos, toPos, stepMask, foundItems;
    PUnitRec    recU;
    PInfoRec    recN;
    MProcInfo   aInfo;
    MProcInfo   *pInfo = &aInfo;
    MConstInfo  acInfo;
    MConstInfo  *cInfo = &acInfo;
    String      className, unitName;

    stepMask = StartProgress(TotalSize, "Scan Exception Directory");
    for (n = 0; n < TotalSize && !Terminated; n++)
    {
        if ((n & stepMask) == 0) UpdateProgress();
        if (idr.IsFlagSet(cfProcStart, n))
        {
            Adr = Pos2Adr(n);
            AnalyzeProc(0, Adr);
            UpdateAddrInStatusBar(Adr);
        }
    }

    StartProgress(UnitsNum, "Scan Ini and Fin");
    //Begin with initialization and finalization procs
    for (n = 0; n < UnitsNum && !Terminated; n++)
    {
        UpdateProgress();
        recU = (UnitRec*)Units->Items[n];
        if (recU->trivial) continue;

        iniAdr = recU->iniadr;
        if (iniAdr && !recU->trivialIni)
        {
            AnalyzeProc(0, iniAdr);

            for (u = 0; u < recU->names->Count && !Terminated; u++)
            {
                moduleID = KnowledgeBase.GetModuleID(recU->names->Strings[u].c_str());
                if (moduleID == 0xFFFF) continue;

                //If unit is in knowledge base try to find proc Initialization
                Idx = KnowledgeBase.GetProcIdx(moduleID, recU->names->Strings[u].c_str());
                if (Idx != -1)
                {
                    Idx = KnowledgeBase.ProcOffsets[Idx].NamId;
                    if (!KnowledgeBase.IsUsedProc(Idx))
                    {
                        if (KnowledgeBase.GetProcInfo(Idx, INFO_DUMP | INFO_ARGS, pInfo))
                        {
                            matched = (MatchCode(Code + Adr2Pos(iniAdr), pInfo) && StrapCheck(Adr2Pos(iniAdr), pInfo));
                            if (matched)
                            {
                                StrapProc(Adr2Pos(iniAdr), Idx, pInfo, true, pInfo->DumpSz);
                            }
                        }
                    }
                }
            }
        }
        finAdr = recU->finadr;
        if (finAdr && !recU->trivialFin)
        {
            AnalyzeProc(0, finAdr);

            for (u = 0; u < recU->names->Count && !Terminated; u++)
            {
                moduleID = KnowledgeBase.GetModuleID(recU->names->Strings[u].c_str());
                if (moduleID == 0xFFFF) continue;

                //If unit is in knowledge base try to find proc Finalization
                Idx = KnowledgeBase.GetProcIdx(moduleID, "Finalization");
                if (Idx != -1)
                {
                    Idx = KnowledgeBase.ProcOffsets[Idx].NamId;
                    if (!KnowledgeBase.IsUsedProc(Idx))
                    {
                        if (KnowledgeBase.GetProcInfo(Idx, INFO_DUMP | INFO_ARGS, pInfo))
                        {
                            matched = (MatchCode(Code + Adr2Pos(finAdr), pInfo) && StrapCheck(Adr2Pos(finAdr), pInfo));
                            if (matched)
                            {
                                StrapProc(Adr2Pos(finAdr), Idx, pInfo, true, pInfo->DumpSz);
                            }
                        }
                    }
                }
            }
        }
    }
    StopProgress();

    //EP
    AnalyzeProc(0, EP);

    //VMT (methods, dynamics procedures, virtual methods)
    stepMask = StartProgress(TotalSize, "Analyze Class Tables");
    for (n = 0; n < TotalSize && !Terminated; n++)
    {
        if ((n & stepMask) == 0) UpdateProgress();
        recN = GetInfoRec(Pos2Adr(n));
    	if (recN && recN->kind == ikVMT)
        {
            vmtAdr = Pos2Adr(n);
            UpdateStatusBar(GetClsName(vmtAdr));

            AnalyzeMethodTable(0, vmtAdr);
            if (Terminated) break;

            AnalyzeDynamicTable(0, vmtAdr);
            if (Terminated) break;

            AnalyzeVirtualTable(0, vmtAdr);
        }
    }
    StopProgress();
    //Scan already defined Units
    for (n = 0; n < UnitsNum && !Terminated; n++)
    {
        recU = (UnitRec*)Units->Items[n];
        if (recU->trivial) continue;

        fromPos = Adr2Pos(recU->fromAdr);
        toPos = Adr2Pos(recU->toAdr);

        for (u = 0; u < recU->names->Count && !Terminated; u++)
        {
            unitName = recU->names->Strings[u];
            moduleID = KnowledgeBase.GetModuleID(unitName.c_str());
            if (moduleID == 0xFFFF) continue;

            if (!KnowledgeBase.GetProcIdxs(moduleID, &FirstProcIdx, &LastProcIdx)) continue;

            stepMask = StartProgress(toPos - fromPos + 1, "Scan Unit " + unitName + " (step 1)"); foundItems = 0;

            for (m = fromPos, i = 0; m < toPos && !Terminated; m++, i++)
            {
                if ((i & stepMask) == 0) UpdateProgress();

                if (!*(Code + m)) continue;
                if (idr.IsFlagSet(cfProcStart, m) || idr.IsFlagEmpty(m))
                {
                    if (Pos2Adr(m) == recU->iniadr && recU->trivialIni) continue;
                    if (Pos2Adr(m) == recU->finadr && recU->trivialFin) continue;
                    recN = GetInfoRec(Pos2Adr(m));
                    if (recN && recN->HasName()) continue;

                    UpdateAddrInStatusBar(Pos2Adr(m));
                    for (k = FirstProcIdx; k <= LastProcIdx && !Terminated; k++)
                    {
                        Idx = KnowledgeBase.ProcOffsets[k].ModId;
                        if (!KnowledgeBase.IsUsedProc(Idx))
                        {
                            if (KnowledgeBase.GetProcInfo(Idx, INFO_DUMP | INFO_ARGS, pInfo) && pInfo->DumpSz >= 8 && m + pInfo->DumpSz < toPos)
                            {
                                //Check code matching
                                matched = (MatchCode(Code + m, pInfo) && StrapCheck(m, pInfo));
                                if (matched)
                                {
//!!!
if (Pos2Adr(m) == 0x00489650)
m = m;
                                    //If method of class, check that ClassName is found
                                    //className = ExtractClassName(pInfo->ProcName);
                                    //if (className == "" || GetOwnTypeByName(className))
                                    //{
                                        StrapProc(m, Idx, pInfo, true, pInfo->DumpSz);
                                        m += pInfo->DumpSz - 1;
                                        foundItems++;
                                        break;
                                    //}
                                }
                            }
                        }
                    }
                }
            }
            StopProgress();
        }
    }
    //Scan PossibleUnitNames
    for (n = 0; n < PossibleUnitNames->Count && !Terminated; n++)
    {
        UpdateProgress();
        unitName = PossibleUnitNames->Strings[n];
        moduleID = KnowledgeBase.GetModuleID(unitName.c_str());
        if (moduleID == 0xFFFF) continue;

        if (!KnowledgeBase.GetProcIdxs(moduleID, &FirstProcIdx, &LastProcIdx)) continue;
        stepMask = StartProgress(TotalSize, "Scan Possible Unit " + unitName);

        for (m = 0; m < TotalSize && !Terminated; m++)
        {
            if ((m & stepMask) == 0) UpdateProgress();

            if (idr.IsFlagSet(cfProcStart, m))
            {
                recN = GetInfoRec(Pos2Adr(m));
                if (recN && recN->HasName())
                {
                    if (recN->procInfo && recN->procInfo->procSize > 0)
                        m += recN->procInfo->procSize - 1;
                    continue;
                }
                UpdateAddrInStatusBar(Pos2Adr(m));
                for (k = FirstProcIdx; k <= LastProcIdx && !Terminated; k++)
                {
                    Idx = KnowledgeBase.ProcOffsets[k].ModId;
                    if (!KnowledgeBase.IsUsedProc(Idx))
                    {
                        matched = false;
                        if (KnowledgeBase.GetProcInfo(Idx, INFO_DUMP, pInfo) && pInfo->DumpSz >= 8 && m + pInfo->DumpSz < TotalSize)
                        {
                            matched = (MatchCode(Code + m, pInfo) && StrapCheck(m, pInfo));
                            if (matched)
                            {
//!!!
if (Pos2Adr(m) == 0x00489650)
m = m;
                                //If method of class, check that ClassName is found
                                //className = ExtractClassName(pInfo->ProcName);
                                //if (className == "" || GetOwnTypeByName(className))
                                //{
                                    StrapProc(m, Idx, pInfo, true, pInfo->DumpSz);
                                    m += pInfo->DumpSz - 1;
                                    break;
                                //}
                            }
                        }
                    }
                }
            }
        }
    }
    StopProgress();

    //Process VMT (find in Knowledge Base)
    stepMask = StartProgress(TotalSize, "Scan VMTs");
    for (n = 0; n < TotalSize && !Terminated; n++)
    {
        if ((n & stepMask) == 0) UpdateProgress();
        PInfoRec recN = GetInfoRec(Pos2Adr(n));
    	if (recN && recN->kind == ikVMT)
        {
            String ConstName = "_DV_" + recN->GetName();
            Num = KnowledgeBase.GetConstIdxs(ConstName.c_str(), &Idx);
            if (Num == 1)
            {
                Adr = Pos2Adr(n);
                recU = GetUnit(Adr);
                if (!recU || recU->trivial) continue;

                if (!recU->names->Count)
                {
                    Idx = KnowledgeBase.ConstOffsets[Idx].NamId;
                    if (KnowledgeBase.GetConstInfo(Idx, INFO_DUMP, cInfo))
                    {
                        moduleID = cInfo->ModuleID;
                        if (!KnowledgeBase.GetProcIdxs(moduleID, &FirstProcIdx, &LastProcIdx)) continue;
                        
                        fromPos = Adr2Pos(recU->fromAdr);
                        toPos = Adr2Pos(recU->toAdr);
                        for (m = fromPos; m < toPos && !Terminated; m++)
                        {
                            if (idr.IsFlagSet(cfProcStart, m))
                            {
                                if (Pos2Adr(m) == recU->iniadr && recU->trivialIni) continue;
                                if (Pos2Adr(m) == recU->finadr && recU->trivialFin) continue;

                                recN = GetInfoRec(Pos2Adr(m));
                                if (recN && recN->HasName()) continue;
                                UpdateAddrInStatusBar(Pos2Adr(m));
                                for (k = FirstProcIdx; k <= LastProcIdx && !Terminated; k++)
                                {
                                    Idx = KnowledgeBase.ProcOffsets[k].ModId;
                                    if (!KnowledgeBase.IsUsedProc(Idx))
                                    {
                                        matched = false;
                                        if (KnowledgeBase.GetProcInfo(Idx, INFO_DUMP | INFO_ARGS, pInfo))
                                        {
                                            matched = (MatchCode(Code + m, pInfo) && StrapCheck(m, pInfo));
                                            if (matched)
                                            {
                                                String unitName = KnowledgeBase.GetModuleName(moduleID);
                                                SetUnitName(recU, unitName);
                                                StrapProc(m, Idx, pInfo, true, pInfo->DumpSz);
                                                m += pInfo->DumpSz - 1;
                                                break;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    StopProgress();
}
//---------------------------------------------------------------------------
void __fastcall TAnalyzeThread::ScanCode1()
{
    bool        matched;
    WORD        moduleID;
    DWORD       pos, Adr;
    int         FirstProcIdx, LastProcIdx, Num, stepMask;
    int         i, n, m, k, r, u, Idx, fromPos, toPos;
    PUnitRec    recU;
    PInfoRec    recN;
    MProcInfo   aInfo;
    MProcInfo   *pInfo = &aInfo;
    String      className, unitName;

    StartProgress(UnitsNum, "ScanCode1");
    for (n = 0; n < UnitsNum && !Terminated; n++)
    {
        UpdateProgress();
        recU = (UnitRec*)Units->Items[n];
        if (recU->trivial) continue;

        fromPos = Adr2Pos(recU->fromAdr);
        toPos = Adr2Pos(recU->toAdr);

        for (u = 0; u < recU->names->Count && !Terminated; u++)
        {
            unitName = recU->names->Strings[u];
            moduleID = KnowledgeBase.GetModuleID(unitName.c_str());
            if (moduleID == 0xFFFF) continue;

            if (!KnowledgeBase.GetProcIdxs(moduleID, &FirstProcIdx, &LastProcIdx)) continue;

            stepMask = StartProgress(toPos - fromPos + 1, "Scan Unit " + unitName + " (step 2)");

            for (m = fromPos, i = 0; m < toPos && !Terminated; m++, i++)
            {
                if ((i & stepMask) == 0) UpdateProgress();

                if (idr.IsFlagSet(cfProcStart, m))
                {
                    if (Pos2Adr(m) == recU->iniadr && recU->trivialIni) continue;
                    if (Pos2Adr(m) == recU->finadr && recU->trivialFin) continue;

                    recN = GetInfoRec(Pos2Adr(m));
                    if (recN && recN->HasName()) continue;
                    UpdateAddrInStatusBar(Pos2Adr(m));
                    for (k = FirstProcIdx; k <= LastProcIdx && !Terminated; k++)
                    {
                        Idx = KnowledgeBase.ProcOffsets[k].ModId;
                        if (!KnowledgeBase.IsUsedProc(Idx))
                        {
                            if (KnowledgeBase.GetProcInfo(Idx, INFO_DUMP | INFO_ARGS, pInfo) && pInfo->DumpSz >= 8 && m + pInfo->DumpSz < toPos)
                            {
                                matched = (MatchCode(Code + m, pInfo) && StrapCheck(m, pInfo));
                                if (matched)
                                {
                                    //If method of class, check that ClassName is found
                                    //className = ExtractClassName(pInfo->ProcName);
                                    //if (className == "" || GetOwnTypeByName(className))
                                    //{
                                        StrapProc(m, Idx, pInfo, true, pInfo->DumpSz);
                                        m += pInfo->DumpSz - 1;
                                        break;
                                    //}
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    StopProgress();
    /*
    //Scan PossibleUnitNames
    //StartProgress(PossibleUnitNames->Count, "Scan Possible Unit Names");
    for (n = 0; n < PossibleUnitNames->Count && !Terminated; n++)
    {
        UpdateProgress();
        moduleID = KnowledgeBase.GetModuleID(PossibleUnitNames->Strings[n].c_str());
        if (moduleID == 0xFFFF) continue;

        if (!KnowledgeBase.GetProcIdxs(moduleID, &FirstProcIdx, &LastProcIdx)) continue;
        stepMask = StartProgress(TotalSize, "Scan Unit " + PossibleUnitNames->Strings[n]);
        
        for (m = fromPos; m < TotalSize && !Terminated; m++)
        {
            if ((m & stepMask) == 0) UpdateProgress();
            
            if (idr.IsFlagSet(cfProcStart, m))
            {
                recN = GetInfoRec(Pos2Adr(m));
                if (recN && recN->HasName())
                {
                    if (recN->procInfo && recN->procInfo->procSize > 0)
                        m += recN->procInfo->procSize - 1;
                    continue;
                }
                UpdateAddrInStatusBar(Pos2Adr(m));
                for (k = FirstProcIdx; k <= LastProcIdx && !Terminated; k++)
                {
                    Idx = KnowledgeBase.ProcOffsets[k].ModId;
                    if (!KnowledgeBase.IsUsedProc(Idx))
                    {
                        matched = false;
                        if (KnowledgeBase.GetProcInfo(Idx, INFO_DUMP, pInfo) && pInfo->DumpSz >= 8 && m + pInfo->DumpSz < TotalSize)
                        {
                            matched = (MatchCode(Code + m, pInfo) && StrapCheck(m, pInfo));
                            if (matched)
                            {
                                //If method of class, check that ClassName is found
                                //className = ExtractClassName(pInfo->ProcName);
                                //if (className == "" || GetOwnTypeByName(className))
                                //{
                                    StrapProc(m, Idx, pInfo, true, pInfo->DumpSz);
                                    m += pInfo->DumpSz - 1;
                                    break;
                                //}
                            }
                        }
                    }
                }
            }
        }
    }
    StopProgress();
    */
}
//---------------------------------------------------------------------------
void __fastcall TAnalyzeThread::ScanVMTs()
{
    int stepMask = StartProgress(TotalSize, "Scan VMTs");
    for (int n = 0; n < TotalSize && !Terminated; n++)
    {
        if ((n & stepMask) == 0) UpdateProgress();
        PInfoRec recN = GetInfoRec(Pos2Adr(n));
    	if (recN && recN->kind == ikVMT)
        {
            DWORD vmtAdr = Pos2Adr(n);
            String name = recN->GetName();
            UpdateStatusBar(name);
            ScanFieldTable(vmtAdr);
            if (Terminated) break;
            ScanMethodTable(vmtAdr, name);
            if (Terminated) break;
            ScanVirtualTable(vmtAdr);
            if (Terminated) break;
            ScanDynamicTable(vmtAdr);
            if (Terminated) break;
            ScanIntfTable(vmtAdr);
            ScanAutoTable(vmtAdr);
            if (Terminated) break;
            ScanInitTable(vmtAdr);
        }
    }
    StopProgress();
}
//---------------------------------------------------------------------------
void __fastcall TAnalyzeThread::ScanConsts()
{
    WORD        ModID;
    int         n, m, u, Bytes, ResStrIdx, pos, ResStrNum, ResStrNo;
	DWORD       adr, resid;
    PUnitRec    recU;
    PInfoRec    recN;
    MResStrInfo arsInfo;
    MResStrInfo *rsInfo = &arsInfo;
    String      uname;
    char        buf[1024];

    if (Terminated) return;
    if (HInstanceVarAdr == 0xFFFFFFFF) return;

    HINSTANCE hInst = LoadLibraryEx(/*mainForm->*/SourceFile.c_str(), 0, LOAD_LIBRARY_AS_DATAFILE);//DONT_RESOLVE_DLL_REFERENCES);
    if (!hInst) return;

    //Array of counters for units frequences
    int *Counters = new int[KnowledgeBase.ModuleCount];

    StartProgress(UnitsNum, "Scan Resource Strings");
    for (m = 0; m < UnitsNum && !Terminated; m++)
    {
        UpdateProgress();
        recU = (PUnitRec)Units->Items[m];
        if (!recU) continue;

        ModID = 0xFFFF;
        //If module from KB load information about ResStrings
        if (recU->names->Count)
        {
            for (u = 0; u < recU->names->Count && !Terminated; u++)
            {
                UpdateAddrInStatusBar(u);
                ModID = KnowledgeBase.GetModuleID(recU->names->Strings[u].c_str());
                //Если из базы знаний, вытащим из нее информацию о ResStr
                if (ModID != 0xFFFF)
                {
                    for (n = Adr2Pos(recU->fromAdr); (n < Adr2Pos(recU->toAdr)) && !Terminated; n += 4)
                    {
                        adr = *((ULONGLONG*)(Code + n));
                        resid = *((DWORD*)(Code + n + 8));

                        if (IsValidImageAdr(adr) && adr == HInstanceVarAdr && resid < 0x10000)
                        {
                            recN = GetInfoRec(Pos2Adr(n));
                            //If export at this position, delete InfoRec and create new (ikResString)
                            if (idr.IsFlagSet(cfExport, n))
                            {
                                idr.ClearFlag(cfProcStart, n);
                                delete recN;
                                recN = 0;
                            }
                            if (!recN)
                                recN = new InfoRec(n, ikResString);
                            else
                            {
                                if (recN->kind == ikResString) continue;
                                //may be ikData
                                if (!recN->rsInfo) recN->rsInfo = new InfoResStringInfo;
                            }
                            recN->type = "TResStringRec";

                            //Set Flags
                            idr.SetFlags(cfData, n, 12);
                            //Get Context
                            Bytes = LoadString(hInst, (UINT)resid, buf, sizeof(buf));
                            recN->rsInfo->value = String(buf, Bytes);

                            ResStrIdx = KnowledgeBase.GetResStrIdx(ModID, buf);
                            if (ResStrIdx != -1)
                            {
                                ResStrIdx = KnowledgeBase.ResStrOffsets[ResStrIdx].NamId;
                                if (KnowledgeBase.GetResStrInfo(ResStrIdx, 0, rsInfo))
                                {
                                    if (!recN->HasName())
                                    {
                                        UpdateStatusBar(rsInfo->ResStrName);
                                        recN->SetName(rsInfo->ResStrName);
                                    }
                                }
                            }
                            else
                            {
                                if (!recN->HasName())
                                {
                                    recN->ConcatName("SResString" + String(LastResStrNo));
                                    LastResStrNo++;
                                }
                            }
                        }
                    }
                }
                //Else extract ResStrings from analyzed file
                else
                {
                    for (n = Adr2Pos(recU->fromAdr); (n < Adr2Pos(recU->toAdr)) && !Terminated; n += 4)
                    {
                        adr = *((ULONGLONG*)(Code + n));
                        resid = *((DWORD*)(Code + n + 8));

                        if (IsValidImageAdr(adr) && adr == HInstanceVarAdr && resid < 0x10000)
                        {
                            recN = GetInfoRec(Pos2Adr(n));
                            //If export at this position, delete InfoRec and create new (ikResString)
                            if (idr.IsFlagSet(cfExport, n))
                            {
                                idr.ClearFlag(cfProcStart, n);
                                delete recN;
                                recN = 0;
                            }
                            if (!recN)
                                recN = new InfoRec(n, ikResString);
                            else
                            {
                                if (recN->kind == ikResString) continue;
                                //may be ikData
                                if (!recN->rsInfo) recN->rsInfo = new InfoResStringInfo;
                            }
                            recN->type = "TResStringRec";

                            //Set Flags
                            idr.SetFlags(cfData, n, 12);
                            //Get Context
                            Bytes = LoadString(hInst, (UINT)resid, buf, sizeof(buf));
                            recN->rsInfo->value = String(buf, Bytes);

                            if (!recN->HasName())
                            {
                                recN->ConcatName("SResString" + String(LastResStrNo));
                                LastResStrNo++;
                            }
                        }
                    }
                }
            }
        }
        //If unit has no name check it is module of ResStrings
        else
        {
            UpdateProgress();
            memset(Counters, 0, KnowledgeBase.ModuleCount*sizeof(int));
            ResStrNum = 0;

            for (n = Adr2Pos(recU->fromAdr); (n < Adr2Pos(recU->toAdr)) && !Terminated; n += 4)
            {
                adr = *((ULONGLONG*)(Code + n));
                resid = *((DWORD*)(Code + n + 8));

                if (IsValidImageAdr(adr) && adr == HInstanceVarAdr && resid < 0x10000)
                {
                    Bytes = LoadString(hInst, (UINT)resid, buf, sizeof(buf));
                    //Number of ReStrings in this module
                    ResStrNum++;
                    for (ResStrNo = 0; !Terminated; )
                    {
                        ResStrIdx = KnowledgeBase.GetResStrIdx(ResStrNo, buf);
                        if (ResStrIdx == -1) break;
                        ResStrNo = ResStrIdx + 1;
                        ResStrIdx = KnowledgeBase.ResStrOffsets[ResStrIdx].NamId;
                        if (KnowledgeBase.GetResStrInfo(ResStrIdx, 0, rsInfo))
                        {
                            Counters[rsInfo->ModuleID]++;
                        }
                    }
                }
            }
            //What module has frequency >= ResStrNum
            if (ResStrNum)
            {
                for (n = 0; n < KnowledgeBase.ModuleCount && !Terminated; n++)
                {
                    if (Counters[n] >= 0.9*ResStrNum)
                    {
                        ModID = n;
                        break;
                    }
                }
                //Module is found
                if (ModID != 0xFFFF)
                {
                    uname = KnowledgeBase.GetModuleName(ModID);
                    SetUnitName(recU, uname);
                    recU->kb = true;

                    for (n = Adr2Pos(recU->fromAdr); (n < Adr2Pos(recU->toAdr)) && !Terminated; n += 4)
                    {
                        adr = *((ULONGLONG*)(Code + n));
                        resid = *((DWORD*)(Code + n + 8));

                        if (IsValidImageAdr(adr) && adr == HInstanceVarAdr && resid < 0x10000)
                        {
                            recN = GetInfoRec(Pos2Adr(n));
                            //If export at this position, delete InfoRec and create new (ikResString)
                            if (idr.IsFlagSet(cfExport, n))
                            {
                                idr.ClearFlag(cfProcStart, n);
                                delete recN;
                                recN = 0;
                            }
                            if (!recN)
                                recN = new InfoRec(n, ikResString);
                            else
                            {
                                if (recN->kind == ikResString) continue;
                                //may be ikData
                            	if (!recN->rsInfo) recN->rsInfo = new InfoResStringInfo;
                            }
                            recN->type = "TResStringRec";

                            //Set Flags
                            idr.SetFlags(cfData, n, 8);
                            //Get Context
                            Bytes = LoadString(hInst, (UINT)resid, buf, sizeof(buf));
                            recN->rsInfo->value = String(buf, Bytes);

                            ResStrIdx = KnowledgeBase.GetResStrIdx(ModID, buf);
                            if (ResStrIdx != -1)
                            {
                                ResStrIdx = KnowledgeBase.ResStrOffsets[ResStrIdx].NamId;
                                if (KnowledgeBase.GetResStrInfo(ResStrIdx, 0, rsInfo))
                                {
                                    if (!recN->HasName())
                                    {
                                        UpdateStatusBar(rsInfo->ResStrName);
                                        recN->SetName(rsInfo->ResStrName);
                                    }
                                }
                            }
                            else
                            {
                                if (!recN->HasName())
                                {
                                    recN->ConcatName("SResString" + String(LastResStrNo));
                                    LastResStrNo++;
                                }
                            }
                        }
                    }
                }
                //Module not found, get ResStrings from analyzed file
                else
                {
                    for (n = Adr2Pos(recU->fromAdr); (n < Adr2Pos(recU->toAdr)) && !Terminated; n += 4)
                    {
                        adr = *((ULONGLONG*)(Code + n));
                        resid = *((DWORD*)(Code + n + 8));

                        if (IsValidImageAdr(adr) && adr == HInstanceVarAdr && resid < 0x10000)
                        {
                            recN = GetInfoRec(Pos2Adr(n));
                            //If export at this position, delete InfoRec and create new (ikResString)
                            if (idr.IsFlagSet(cfExport, n))
                            {
                                idr.ClearFlag(cfProcStart, n);
                                delete recN;
                                recN = 0;
                            }
                            if (!recN)
                                recN = new InfoRec(n, ikResString);
                            else
                            {
                                if (recN->kind == ikResString) continue;
                                //may be ikData
                                if (!recN->rsInfo) recN->rsInfo = new InfoResStringInfo;
                            }
                            recN->type = "TResStringRec";

                            //Set Flags
                            idr.SetFlags(cfData, n, 8);
                            //Get Context
                            Bytes = LoadString(hInst, (UINT)resid, buf, sizeof(buf));
                            recN->rsInfo->value = String(buf, Bytes);

                            if (!recN->HasName())
                            {
                                recN->ConcatName("SResString" + String(LastResStrNo));
                                LastResStrNo++;
                            }
                        }
                    }
                }
            }
        }
    }
    FreeLibrary(hInst);    
    StopProgress();
    delete[] Counters;
}
//---------------------------------------------------------------------------
void __fastcall TAnalyzeThread::ScanGetSetStoredProcs()
{
    for (int m = 0; m < OwnTypeList->Count && !Terminated; m++)
    {
        PTypeRec recT = (PTypeRec)OwnTypeList->Items[m];
        if (recT->kind == ikClass)
        {
            int n = Adr2Pos(recT->adr);
            //SelfPtr
            n += 8;
            //typeKind
            n++;
            BYTE len = Code[n]; n++;
            //clsName
            n += len;

            DWORD classVMT = *((ULONGLONG*)(Code + n)); n += 8;
            PInfoRec recN1 = GetInfoRec(classVMT + Vmt.SelfPtr);
            /*DWORD parentAdr = *((ULONGLONG*)(Code + n));*/ n += 8;
            WORD propCount = *((WORD*)(Code + n)); n += 2;
            //Skip unit name
            len = Code[n]; n++;
            n += len;
            //Real properties count
            propCount = *((WORD*)(Code + n)); n += 2;

            for (int i = 0; i < propCount && !Terminated; i++)
            {
                DWORD propType = *((ULONGLONG*)(Code + n)); n += 8;
                int posn = Adr2Pos(propType);
                posn += 8;
                posn++; //property type
                len = Code[posn]; posn++;
                String fieldType = String((char*)(Code + posn), len);

                ULONGLONG getProc = *((ULONGLONG*)(Code + n)); n += 8;
                ULONGLONG setProc = *((ULONGLONG*)(Code + n)); n += 8;
                ULONGLONG storedProc = *((ULONGLONG*)(Code + n)); n += 8;
                //idx
                n += 4;
                //defval
                n += 4;
                //nameIdx
                n += 2;
                len = Code[n]; n++;
                String fieldName = String((char*)(Code + n), len); n += len;

                int fieldOfs = -1;
                if ((getProc & 0xFFFFFF0000000000))
                {
                    if ((getProc & 0xFF00000000000000) == 0xFF00000000000000)
                        fieldOfs = getProc & 0x0FFFFFF;
                }
                if ((setProc & 0xFFFFFF0000000000))
                {
                    if ((setProc & 0xFF00000000000000) == 0xFF00000000000000)
                        fieldOfs = setProc & 0x0FFFFFF;
                }
                if ((storedProc & 0xFFFFFF0000000000))
                {
                    if ((storedProc & 0xFF00000000000000) == 0xFF00000000000000)
                        fieldOfs = storedProc & 0x0FFFFFF;
                }
                if (recN1 && fieldOfs != -1) recN1->vmtInfo->AddField(0, 0, FIELD_PUBLIC, fieldOfs, -1, fieldName, fieldType);
            }
        }
    }
}
//---------------------------------------------------------------------------
//LString
//RefCnt     Length     Data
//0          4          8
//                      recN (kind = ikLString, name = context)
//UString
//CodePage  ElemSz  RefCnt  Length  Data
//0         2       4       8       12
//                                  recN (kind = ikUString, name = context)
void __fastcall TAnalyzeThread::FindStrings()
{
    int			i, len, stepMask;
    WORD        codePage, elemSize;
    DWORD		refCnt;
    PInfoRec	recN;

    stepMask = StartProgress(CodeSize, "Scan UStrings");
    //Scan UStrings
    for (i = 0; i < CodeSize && !Terminated; i += 4)
    {
        if ((i & stepMask) == 0) UpdateProgress();
        if (idr.IsFlagSet(cfData, i)) continue;

        codePage = *((WORD*)(Code + i));
        elemSize = *((WORD*)(Code + i + 2));
        if (!elemSize || elemSize > 4) continue;
        refCnt = *((DWORD*)(Code + i + 4));
        if (refCnt != 0xFFFFFFFF) continue;
        //len = wcslen((wchar_t*)(Code + i + 12));
        len = *((int*)(Code + i + 8));
        if (len <= 0 || len > 10000) continue;
        if (i + 12 + (len + 1)*elemSize >= CodeSize) continue;
        if (!idr.HasInfosAt(i + 12))
        {
            UpdateAddrInStatusBar(Pos2Adr(i));
            recN = new InfoRec(i + 12, ikUString);
            if (elemSize == 1)
                recN->SetName(TransformString(Code + i + 12, len));
            else
                recN->SetName(TransformUString(codePage, (wchar_t*)(Code + i + 12), len));
        }
        //Align to 4 bytes
        len = (12 + (len + 1)*elemSize + 3) & (-4);
        idr.SetFlags(cfData, i, len);
    }
    StopProgress();

    stepMask = StartProgress(CodeSize, "Scan LStrings");
    //Scan LStrings
    for (i = 0; i < CodeSize && !Terminated; i += 4)
    {
        if ((i & stepMask) == 0) UpdateProgress();
        if (idr.IsFlagSet(cfData, i)) continue;

        refCnt = *((DWORD*)(Code + i));
        if (refCnt != 0xFFFFFFFF) continue;
        len = *((int*)(Code + i + 4));
        if (len <= 0 || len > 10000) continue;
        if (i + 8 + len + 1 >= CodeSize) continue;
        //Check last 0
        if (*(Code + i + 8 + len)) continue;
        //Check flags
        //!!!
        if (!idr.HasInfosAt(i + 8))
        {
            UpdateAddrInStatusBar(Pos2Adr(i));
        	recN = new InfoRec(i + 8, ikLString);
            recN->SetName(TransformString(Code + i + 8, len));
        }
        //Align to 4 bytes
        len = (8 + len + 1 + 3) & (-4);
        idr.SetFlags(cfData, i, len);
    }
    StopProgress();
}
//---------------------------------------------------------------------------
void __fastcall TAnalyzeThread::AnalyzeCode1()
{
    String      msg = "AnalyzeCode1";
    PUnitRec    recU;
    DWORD       vmtAdr, Adr;
/*
    StartProgress(UnitsNum, msg);

    //Initialization and Finalization procedures
    for (int n = 0; n < UnitsNum && !Terminated; n++)
    {
        UpdateProgress();
        recU = (UnitRec*)Units->Items[n];
        if (recU)
        {
            DWORD iniAdr = recU->iniadr;
            if (iniAdr)
            {
                UpdateStatusBar(iniAdr);
                AnalyzeProc(1, iniAdr);
            }
            DWORD finAdr = recU->finadr;
            if (finAdr)
            {
                UpdateStatusBar(finAdr);
                AnalyzeProc(1, finAdr);
            }
        }
    }
    StopProgress();
*/
    //EP
    AnalyzeProc(1, EP);
    
    int stepMask = StartProgress(TotalSize, msg);
    //Classes (methods, dynamics procedures, virtual methods)
    for (int n = 0; n < TotalSize && !Terminated; n++)
    {
        if ((n & stepMask) == 0) UpdateProgress();
        PInfoRec recN = GetInfoRec(Pos2Adr(n));
    	if (recN && recN->kind == ikVMT)
        {
            vmtAdr = Pos2Adr(n);
            UpdateAddrInStatusBar(vmtAdr);

            AnalyzeMethodTable(1, vmtAdr);
            if (Terminated) break;

            AnalyzeDynamicTable(1, vmtAdr);
            if (Terminated) break;

            AnalyzeVirtualTable(1, vmtAdr);
        }
    }
    StopProgress();
    //All procs
    stepMask = StartProgress(TotalSize, msg);
    for (int n = 0; n < TotalSize && !Terminated; n++)
    {
        if ((n & stepMask) == 0) UpdateProgress();
        if (idr.IsFlagSet(cfProcStart, n))
        {
            Adr = Pos2Adr(n);
            UpdateAddrInStatusBar(Adr);
            AnalyzeProc(1, Adr);
        }
    }
    StopProgress();
}
//---------------------------------------------------------------------------
void __fastcall TAnalyzeThread::AnalyzeCode2(bool args)
{
    PUnitRec    recU;

    //EP
    AnalyzeProc(2, EP);

    int stepMask = StartProgress(TotalSize, "AnalyzeCode2");
    for (int n = 0; n < TotalSize && !Terminated; n++)
    {
        if ((n & stepMask) == 0) UpdateProgress();
        if (idr.IsFlagSet(cfProcStart, n))
        {
            DWORD adr = Pos2Adr(n);
            UpdateAddrInStatusBar(adr);
            if (args) idr.AnalyzeArguments(adr);
            AnalyzeProc(2, adr);
        }
    }
    StopProgress();
}
//---------------------------------------------------------------------------
void __fastcall TAnalyzeThread::PropagateClassProps()
{
    PInfoRec    recN, recN1;

    int stepMask = StartProgress(TotalSize, "PropagateClassProps");
    for (int n = 0; n < TotalSize && !Terminated; n += 8)
    {
        if ((n & stepMask) == 0) UpdateProgress();
        recN = GetInfoRec(Pos2Adr(n));
    	if (recN && recN->HasName())
        {
            BYTE typeKind = recN->kind;
            if (typeKind > ikProcedure) continue;
            //Пройдемся по свойствам класса и поименуем процедуры
            if (typeKind == ikClass)
            {
                int pos = n;
                //SelfPointer
                pos += 8;
                //TypeKind
                pos++;
                BYTE len = Code[pos]; pos++;
                String clsName = String((char*)(Code + pos), len); pos += len;
                DWORD classVMT = *((ULONGLONG*)(Code + pos)); pos += 8;
                pos += 8;   //ParentAdr
                pos += 2;   //PropCount
                //UnitName
                len = Code[pos]; pos++;
                pos += len;
                WORD propCount = *((WORD*)(Code + pos)); pos += 2;

                for (int i = 0; i < propCount && !Terminated; i++)
                {
                    DWORD propType = *((ULONGLONG*)(Code + pos)); pos += 8;
                    int posn = Adr2Pos(propType); posn += 8;
                    posn++; //property type
                    len = Code[posn]; posn++;
                    String typeName = String((char*)(Code + posn), len);

                    LONGLONG getProc = *((ULONGLONG*)(Code + pos)); pos += 8;
                    LONGLONG setProc = *((ULONGLONG*)(Code + pos)); pos += 8;
                    LONGLONG storedProc = *((ULONGLONG*)(Code + pos)); pos += 8;
                    pos += 4;   //Idx
                    pos += 4;   //DefVal
                    pos += 2;   //NameIdx
                    len = Code[pos]; pos++;
                    String name = String((char*)(Code + pos), len); pos += len;

                    int vmtofs, fieldOfs;
                    PFIELDINFO fInfo;

                    if ((getProc & 0xFFFFFF0000000000))
                    {
                        if ((getProc & 0xFF00000000000000) == 0xFF00000000000000)
                        {
                            fieldOfs = getProc & 0x0FFFFFF;
                            recN1 = GetInfoRec(classVMT + Vmt.SelfPtr);
                            if (recN1 && recN1->vmtInfo)
                                recN1->vmtInfo->AddField(0, 0, FIELD_PUBLIC, fieldOfs, -1, name, typeName);
                        }
                        else if ((getProc & 0xFF00000000000000) == 0xFE00000000000000)
                        {
                            if ((getProc & 0x08000))
                                vmtofs = -((int)getProc & 0x0FFFF);
                            else
                                vmtofs = getProc & 0x0FFFF;
                            posn = Adr2Pos(classVMT) + vmtofs;
                            getProc = *((ULONGLONG*)(Code + posn));
                            recN1 = GetInfoRec(getProc);
                            if (!recN1)
                                recN1 = new InfoRec(Adr2Pos(getProc), ikFunc);
                            else if (!recN1->procInfo)
                                recN1->procInfo = new InfoProcInfo;

                            recN1->kind = ikFunc;
                            recN1->type = typeName;
                            if (!recN1->HasName())
                                recN1->SetName(clsName + ".Get" + name);
                            recN1->procInfo->flags |= PF_METHOD;
                            recN1->procInfo->AddArg(0x21, 0, 4, "Self", clsName);
                            idr.AnalyzeProc1(getProc, 0, 0, 0, false);
                        }
                        else
                        {
                            recN1 = GetInfoRec(getProc);
                            if (!recN1)
                                recN1 = new InfoRec(Adr2Pos(getProc), ikFunc);
                            else if (!recN1->procInfo)
                                recN1->procInfo = new InfoProcInfo;
                            recN1->kind = ikFunc;
                            if (!recN1->HasName())
                                recN1->SetName(clsName + ".Get" + name);
                            recN1->procInfo->flags |= PF_METHOD;
                            recN1->procInfo->AddArg(0x21, 0, 4, "Self", clsName);
                            idr.AnalyzeProc1(getProc, 0, 0, 0, false);
                        }
                    }
                    if ((setProc & 0xFFFFFF0000000000))
                    {
                        if ((setProc & 0xFF00000000000000) == 0xFF00000000000000)
                        {
                            fieldOfs = setProc & 0x0FFFFFF;
                            recN1 = GetInfoRec(classVMT + Vmt.SelfPtr);
                            if (recN1 && recN1->vmtInfo)
                                recN1->vmtInfo->AddField(0, 0, FIELD_PUBLIC, fieldOfs, -1, name, typeName);
                        }
                        else if ((setProc & 0xFF00000000000000) == 0xFE00000000000000)
                        {
                            if ((setProc & 0x08000))
                                vmtofs = -((int)setProc & 0x0FFFF);
                            else
                                vmtofs = setProc & 0x0FFFF;
                            posn = Adr2Pos(classVMT) + vmtofs;
                            setProc = *((ULONGLONG*)(Code + posn));
                            recN1 = GetInfoRec(setProc);
                            if (!recN1)
                                recN1 = new InfoRec(Adr2Pos(setProc), ikProc);
                            else if (!recN1->procInfo)
                                recN1->procInfo = new InfoProcInfo;
                            recN1->kind = ikProc;
                            if (!recN1->HasName())
                                recN1->SetName(clsName + ".Set" + name);
                            recN1->procInfo->flags |= PF_METHOD;
                            recN1->procInfo->AddArg(0x21, 0, 4, "Self", clsName);
                            recN1->procInfo->AddArg(0x21, 1, 4, "Value", typeName);
                            idr.AnalyzeProc1(setProc, 0, 0, 0, false);
                        }
                        else
                        {
                            recN1 = GetInfoRec(setProc);
                            if (!recN1)
                                recN1 = new InfoRec(Adr2Pos(setProc), ikProc);
                            else if (!recN1->procInfo)
                                recN1->procInfo = new InfoProcInfo;
                            recN1->kind = ikProc;
                            if (!recN1->HasName())
                                recN1->SetName(clsName + ".Set" + name);
                            recN1->procInfo->flags |= PF_METHOD;
                            recN1->procInfo->AddArg(0x21, 0, 4, "Self", clsName);
                            recN1->procInfo->AddArg(0x21, 1, 4, "Value", typeName);
                            idr.AnalyzeProc1(setProc, 0, 0, 0, false);
                        }
                    }
                    if ((storedProc & 0xFFFFFF0000000000))
                    {
                        if ((storedProc & 0xFF00000000000000) == 0xFF00000000000000)
                        {
                            fieldOfs = storedProc & 0x0FFFFFF;
                            recN1 = GetInfoRec(classVMT + Vmt.SelfPtr);
                            if (recN1 && recN1->vmtInfo)
                                recN1->vmtInfo->AddField(0, 0, FIELD_PUBLIC, fieldOfs, -1, name, typeName);
                        }
                        else if ((storedProc & 0xFF00000000000000) == 0xFE00000000000000)
                        {
                            if ((storedProc & 0x08000))
                                vmtofs = -((int)storedProc & 0x0FFFF);
                            else
                                vmtofs = storedProc & 0x0FFFF;
                            posn = Adr2Pos(classVMT) + vmtofs;
                            storedProc = *((ULONGLONG*)(Code + posn));
                            recN1 = GetInfoRec(storedProc);
                            if (!recN1)
                                recN1 = new InfoRec(Adr2Pos(storedProc), ikFunc);
                            else if (!recN1->procInfo)
                                recN1->procInfo = new InfoProcInfo;
                            recN1->kind = ikFunc;
                            recN1->type = "Boolean";
                            if (!recN1->HasName())
                                recN1->SetName(clsName + ".IsStored" + name);
                            recN1->procInfo->flags |= PF_METHOD;
                            recN1->procInfo->AddArg(0x21, 0, 4, "Self", clsName);
                            recN1->procInfo->AddArg(0x21, 1, 4, "Value", typeName);
                            idr.AnalyzeProc1(storedProc, 0, 0, 0, false);
                        }
                        else
                        {
                            recN1 = GetInfoRec(storedProc);
                            if (!recN1)
                                recN1 = new InfoRec(Adr2Pos(storedProc), ikFunc);
                            else if (!recN1->procInfo)
                                recN1->procInfo = new InfoProcInfo;
                            recN1->kind = ikFunc;
                            recN1->type = "Boolean";
                            if (!recN1->HasName())
                                recN1->SetName(clsName + ".IsStored" + name);
                            recN1->procInfo->flags |= PF_METHOD;
                            recN1->procInfo->AddArg(0x21, 0, 4, "Self", clsName);
                            recN1->procInfo->AddArg(0x21, 1, 4, "Value", typeName);
                            idr.AnalyzeProc1(storedProc, 0, 0, 0, false);
                        }
                    }
                }
            }
        }
    }
    StopProgress();
}
//---------------------------------------------------------------------------
void __fastcall TAnalyzeThread::AnalyzeDC()
{
    int         n, m, k, dotpos, pos, stepMask, instrLen;
    DWORD       vmtAdr, adr, procAdr, stopAt, classAdr;
    String      className, name;
    PVmtListRec recV;
    PInfoRec    recN, recN1, recN2;
    PARGINFO    argInfo;
    PMethodRec  recM, recM1;
    DISINFO     disInfo;

    //Create temp list of pairs (height, VMT address)
    const int cntVmt = VmtList->Count;
    if (!cntVmt) return;

    stepMask = StartProgress(cntVmt, "AnalyzeDC");
    for (n = 0; n < cntVmt && !Terminated; n++)
    {
        if ((n & stepMask) == 0) UpdateProgress();
        recV = (PVmtListRec)VmtList->Items[n];
        vmtAdr = recV->vmtAdr;
        className = GetClsName(vmtAdr);
        UpdateStatusBar(className);

        //Destructor
        pos = Adr2Pos(vmtAdr) - Vmt.SelfPtr + Vmt.Destroy;
        adr = *((ULONGLONG*)(Code + pos));
        if (IsValidImageAdr(adr))
        {
            recN = GetInfoRec(adr);
            if (recN && !recN->HasName())
            {
                recN->kind = ikDestructor;
                recN->SetName(className + ".Destroy");
            }
        }
        //Constructor
        recN = GetInfoRec(vmtAdr);

        if (recN && recN->xrefs)
        {
            for (m = 0; m < recN->xrefs->Count; m++)
            {
                PXrefRec recX = (PXrefRec)recN->xrefs->Items[m];
                adr = recX->adr + recX->offset;
                recN1 = GetInfoRec(adr);
                if (recN1 && !recN1->HasName())
                {
                    if (idr.IsFlagSet(cfProcStart, Adr2Pos(adr)))
                    {
                        recN1->kind = ikConstructor;
                        recN1->SetName(className + ".Create");
                    }
                }
            }
        }
    }
    StopProgress();
    stepMask = StartProgress(cntVmt, "Analyzing Constructors");
    for (n = 0; n < cntVmt && !Terminated; n++)
    {
        if ((n & stepMask) == 0) UpdateProgress();
        recV = (PVmtListRec)VmtList->Items[n];
        vmtAdr = recV->vmtAdr;
        stopAt = GetStopAt(vmtAdr - Vmt.SelfPtr);
        if (vmtAdr == stopAt) continue;

        className = GetClsName(vmtAdr);
        UpdateStatusBar(className);
        pos = Adr2Pos(vmtAdr) - Vmt.SelfPtr + Vmt.Parent + 8;

        for (m = Vmt.Parent + 8;; m += 8, pos += 8)
        {
            if (Pos2Adr(pos) == stopAt) break;
            procAdr = *((ULONGLONG*)(Code + pos));
            if (m >= 0)
            {
                recN = GetInfoRec(procAdr);
                if (recN && recN->kind == ikConstructor && !recN->HasName())
                {
                    classAdr = vmtAdr;
                    while (classAdr)
                    {
                        recM = GetMethodInfo(classAdr, 'V', m);
                        if (recM)
                        {
                            name = recM->name;
                            if (name != "")
                            {
                                dotpos = name.Pos(".");
                                if (dotpos)
                                    recN->SetName(className + name.SubString(dotpos, name.Length()));
                                else
                                    recN->SetName(name);
                                break;
                            }
                        }
                        classAdr = GetParentAdr(classAdr);
                    }
                }
            }
        }
    }
    StopProgress();
    stepMask = StartProgress(cntVmt, "Analyzing Dynamic Methods");
    for (n = 0; n < cntVmt && !Terminated; n++)
    {
        if ((n & stepMask) == 0) UpdateProgress();
        recV = (PVmtListRec)VmtList->Items[n];
        vmtAdr = recV->vmtAdr;
        className = GetClsName(vmtAdr);
        UpdateStatusBar(className);

        recN = GetInfoRec(vmtAdr);

        if (recN && recN->vmtInfo->methods)
        {
            for (m = 0; m < recN->vmtInfo->methods->Count; m++)
            {
                recM = (PMethodRec)recN->vmtInfo->methods->Items[m];
                if (recM->kind == 'D')
                {
                    recN1 = GetInfoRec(recM->address);
                    if (recN1)
                    {
                        classAdr = GetParentAdr(vmtAdr);
                        while (classAdr)
                        {
                            recM1 = GetMethodInfo(classAdr, 'D', recM->id);
                            if (recM1)
                            {
                                recN2 = GetInfoRec(recM1->address);
                                if (recN2 && recN2->procInfo->args)
                                {
                                    for (k = 0; k < recN2->procInfo->args->Count; k++)
                                    {
                                        if (!k)
                                            recN1->procInfo->AddArg(0x21, 0, 4, "Self", className);
                                        else
                                        {
                                            argInfo = (PARGINFO)recN2->procInfo->args->Items[k];
                                            recN1->procInfo->AddArg(argInfo);
                                        }
                                    }
                                }
                            }
                            classAdr = GetParentAdr(classAdr);
                        }
                    }
                }
            }
        }
    }
    StopProgress();
}
//---------------------------------------------------------------------------
void __fastcall TAnalyzeThread::ClearPassFlags()
{
    if (!Terminated)
        idr.ClearFlags(cfPass0 | cfPass1 | cfPass2 | cfPass, 0, TotalSize);
}
//---------------------------------------------------------------------------
void __fastcall TAnalyzeThread::AnalyzeProc(int pass, DWORD procAdr)
{
    switch (pass)
    {
    case 0:
        idr.AnalyzeProcInitial(procAdr);
        break;
    case 1:
        idr.AnalyzeProc1(procAdr, 0, 0, 0, false);
        break;
    case 2:
        idr.AnalyzeProc2(procAdr, true, true);
        break;
    }
}
//---------------------------------------------------------------------------
void __fastcall TAnalyzeThread::AnalyzeMethodTable(int Pass, DWORD Adr)
{
    BYTE        sLen, paramFlags, paramCount, cc;
    WORD        skipNext, dw, parOfs;
    int         procPos;
    DWORD       procAdr, paramType, resultType;
    PInfoRec    recN;
    String      paramName, methodName;
    DWORD vmtAdr = Adr - Vmt.SelfPtr;
    DWORD methodAdr = *((DWORD*)(Code + Adr2Pos(vmtAdr) + Vmt.MethodTable));

    if (!methodAdr) return;

	String className = GetClsName(Adr);
    int pos = Adr2Pos(methodAdr);
    WORD count = *((WORD*)(Code + pos)); pos += 2;

    for (int n = 0; n < count && !Terminated; n++)
    {
        skipNext = *((WORD*)(Code + pos));
        procAdr = *((ULONGLONG*)(Code + pos + 2));
        procPos = Adr2Pos(procAdr);
        sLen = Code[pos + 10];
        methodName = String((char*)(Code + pos + 11), sLen);

        AnalyzeProc(Pass, procAdr);

        if (Pass == 1)
        {
            recN = GetInfoRec(procAdr);
            if (recN && recN->kind != ikConstructor && recN->kind != ikDestructor && recN->kind != ikClassRef)
            {
                recN->SetName(className + "." + methodName);
                recN->kind = ikProc;
                recN->AddXref('D', Adr, 0);
                recN->procInfo->AddArg(0x21, 0, 4, "Self", className);
            }
        }
        pos += skipNext;
    }
    WORD exCount = *((WORD*)(Code + pos)); pos += 2;
    for (int n = 0; n < exCount && !Terminated; n++)
    {
        DWORD methodEntry = *((ULONGLONG*)(Code + pos)); pos += 8;
        WORD flags = *((WORD*)(Code + pos)); pos += 2;
        WORD vIndex = *((WORD*)(Code + pos)); pos += 2;
        int spos = pos;
        pos = Adr2Pos(methodEntry);
        //Length
        skipNext = *((WORD*)(Code + pos)); pos += 2;
        procAdr = *((DWORD*)(Code + pos)); pos += 8;
        procPos = Adr2Pos(procAdr);
        sLen = Code[pos];
        methodName = String((char*)(Code + pos + 1), sLen); pos += sLen + 1;

        if (procAdr == Adr) continue;

        recN = GetInfoRec(procAdr);
        //IMHO it means that methods are pure virtual calls and must be readed in child classes
        if (recN && recN->kind == ikVMT)
        {
            pos = spos;
            continue;
        }
        AnalyzeProc(Pass, procAdr);
        recN = GetInfoRec(procAdr);

        if (Pass == 1)
        {
            if (recN && recN->procInfo && recN->kind != ikConstructor && recN->kind != ikDestructor)//recN->kind != ikClassRef
            {
                recN->SetName(className + "." + methodName);
                recN->kind = ikProc;
                recN->AddXref('D', Adr, 0);
                recN->procInfo->AddArg(0x21, 0, 4, "Self", className);
            }
        }
        if (pos - Adr2Pos(methodEntry) < skipNext)
        {
            //Version
            pos++;
            cc = Code[pos]; pos++;
            resultType = *((ULONGLONG*)(Code + pos)); pos += 8;
            //ParOff
            pos += 2;
            if (Pass == 1)
            {
                if (recN && recN->procInfo && recN->kind != ikConstructor && recN->kind != ikDestructor)//recN->kind != ikClassRef)
                {
                    if (resultType)
                    {
                        recN->kind = ikFunc;
                        recN->type = GetTypeName(resultType);
                    }
                    if (cc != 0xFF) recN->procInfo->flags |= cc;
                }
            }
            paramCount = Code[pos]; pos++;
            if (Pass == 1)
            {
                if (recN && recN->procInfo)
                {
                    recN->procInfo->DeleteArgs();
                    if (!paramCount) recN->procInfo->AddArg(0x21, 0, 4, "Self", className);
                }
            }
            for (int m = 0; m < paramCount && !Terminated; m++)
            {
                paramFlags = Code[pos]; pos++;
                paramType = *((ULONGLONG*)(Code + pos)); pos += 8;
                //ParOff
                parOfs = *((WORD*)(Code + pos)); pos += 2;
                sLen = Code[pos];
                paramName = String((char*)(Code + pos + 1), sLen); pos += sLen + 1;
                //AttrData
                dw = *((WORD*)(Code + pos));
                pos += dw;//ATR!!
                if (paramFlags & 0x40) continue;//Result
                if (Pass == 1)
                {
                    if (recN && recN->procInfo)//recN->kind != ikClassRef)
                    {
                        Byte tag = 0x21;
                        if (paramFlags & 1) tag = 0x22;
                        recN->procInfo->AddArg(tag, parOfs, 4, paramName, GetTypeName(paramType));
                    }
                }
            }
        }
        else
        {
            cc = 0xFF;
            paramCount = 0;
        }
        pos = spos;
    }
}
//---------------------------------------------------------------------------
void __fastcall TAnalyzeThread::AnalyzeDynamicTable(int Pass, DWORD Adr)
{
    DWORD   vmtAdr = Adr - Vmt.SelfPtr;
    DWORD   DynamicAdr = *((DWORD*)(Code + Adr2Pos(vmtAdr) + Vmt.DynamicTable));
    if (!DynamicAdr) return;

	String clsName = GetClsName(Adr);
    DWORD pos = Adr2Pos(DynamicAdr);
    WORD Num = *((WORD*)(Code + pos)); pos += 2;
    DWORD post = pos + 2 * Num;

    for (int i = 0; i < Num && !Terminated; i++, post += 4)
    {
        //WORD Msg
        pos += 2;
        DWORD procAdr = *((ULONGLONG*)(Code + post));
        int procPos = Adr2Pos(procAdr);
        if (!procPos) continue;//Something wrong!
        bool skip = (*(Code + procPos) == 0 && *(Code + procPos + 1) == 0);
        if (!skip) AnalyzeProc(Pass, procAdr);

        if (Pass == 1 && !skip)
        {
            PInfoRec recN = GetInfoRec(procAdr);
            if (recN)
            {
                recN->kind = ikProc;
                recN->procInfo->flags |= PF_DYNAMIC;
                recN->AddXref('D', Adr, 0);
                recN->procInfo->AddArg(0x21, 0, 4, "Self", clsName);
            }
        }
    }
}
//---------------------------------------------------------------------------
void __fastcall TAnalyzeThread::AnalyzeVirtualTable(int Pass, DWORD Adr)
{
    DWORD   parentAdr = GetParentAdr(Adr);
    DWORD   vmtAdr = Adr - Vmt.SelfPtr;
    DWORD   stopAt = GetStopAt(vmtAdr);
    if (vmtAdr == stopAt) return;
    
    int pos = Adr2Pos(vmtAdr) + Vmt.Parent + 8;
    for (int n = Vmt.Parent + 8; !Terminated; n += 8, pos += 8)
    {
        if (Pos2Adr(pos) == stopAt) break;
        DWORD procAdr = *((ULONGLONG*)(Code + pos));
        int procPos = Adr2Pos(procAdr);
        bool skip = (*(Code + procPos) == 0 && *(Code + procPos + 1) == 0);
        if (!skip) AnalyzeProc(Pass, procAdr);
        PInfoRec recN = GetInfoRec(procAdr);

        if (recN)
        {
            if (Pass == 1 && !skip)
            {
                recN->procInfo->flags |= PF_VIRTUAL;
                recN->AddXref('D', Adr, 0);
            }

            DWORD pAdr = parentAdr;
            while (pAdr&& !Terminated)
            {
                PInfoRec recN1 = GetInfoRec(pAdr);
                //Look at parent class methods
                if (recN1 && recN1->vmtInfo && recN1->vmtInfo->methods)
                {
                    for (int m = 0; m < recN1->vmtInfo->methods->Count; m++)
                    {
                        PMethodRec recM = (PMethodRec)recN1->vmtInfo->methods->Items[m];
                        if (recM->abstract && recM->kind == 'V' && recM->id == n && recM->name == "")
                        {
                            String procName = recN->GetName();
                            if (procName != "" && !SameText(procName, "@AbstractError"))
                            {
                                recM->name = GetClsName(pAdr) + "." + ExtractProcName(procName);
                            }
                            break;
                        }
                    }
                }
                pAdr = GetParentAdr(pAdr);
            }
        }
    }
}
//---------------------------------------------------------------------------
