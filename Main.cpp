//---------------------------------------------------------------------------
#define NO_WIN32_LEAN_AND_MEAN
#include <vcl.h>
#pragma hdrstop

#include <ComCtrls.hpp>
#include <Chart.hpp>
#include <Outline.hpp>
#include <Tabnotbk.hpp>
#include <IniFiles.hpp>

#include <dir.h>
#include <io.h>
#include <assert>

#include "Main.h"
#include "Misc.h"
#include "Threads.h"
#include "ProgressBar.h"
#include "TypeInfo.h"
#include "StringInfo.h"
#include "StrUtils.hpp"
#include "FindDlg.h"
#include "InputDlg.h"
#include "Disasm.h"
#include "Explorer.h"
#include "KBViewer.h"
#include "EditFunctionDlg.h"
#include "EditFieldsDlg.h"
#include "AboutDlg.h"
#include "Legend.h"
#include "IDCGen.h"
#include "Decompiler.h"
#include "Hex2Double.h"
#include "Plugins.h"
#include "ActiveProcesses.h"
//---------------------------------------------------------------------------
#pragma package(smart_init)
#pragma resource "*.dfm"

#pragma resource "idr_manifest.res"
//---------------------------------------------------------------------------
//---------------------------------------------------------------------------
SysProcInfo    SysProcs[SYSPROCSNUM] = {
//    {"@HandleFinally", 0},
//    {"@HandleAnyException", 0},
//    {"@HandleOnException", 0},
//    {"@HandleAutoException", 0},
    {"@RunError", 0},
    {"@Halt0", 0},
    {"@AbstractError", 0}
};
SysProcInfo    SysInitProcs[SYSINITPROCSNUM] = {
    {"@InitExe", 0},
    {"@InitLib", 0},
};
//Image       Code
//|===========|======================================|
//ImageBase   CodeBase
//---------------------------------------------------------------------------
char    StringBuf[MAXSTRBUFFER];    //Buffer to make string

String      SourceFile;

extern  RegClassInfo RegClasses[];

int             dummy = 0;          //for debugging purposes!!!

//MDisasm         Disasm(GetSyncObj());//Дизассемблер для анализатора кода
MKnowledgeBase  KnowledgeBase;
//->idrMgr TResourceInfo   *ResInfo = 0;       //Information about forms

//Common variables
String          IDPFile;
int             MaxBufLen;      //Максимальная длина буфера (для загрузки)
int             DelphiVersion;
DWORD           InitTable = 0;
DWORD           EP;
DWORD           ImageBase;
DWORD           ImageSize;
DWORD           TotalSize;      //Size of sections CODE + DATA
DWORD           CodeBase;
DWORD           CodeSize;
DWORD           CodeStart;
DWORD           DataBase = 0;
DWORD           DataSize = 0;
DWORD           DataStart = 0;
BYTE            *Image = 0;
//->Misc (TBD: idr manager)
//PInfoRec        *Infos = 0;	    //Array of pointers to store items data
//TStringList     *BSSInfos = 0;  //Data from BSS
BYTE            *Code = 0;
BYTE            *Data = 0;

static TList           *ExpFuncList;   //Exported functions list (temporary)
static TList           *ImpFuncList;   //Imported functions list (temporary)
static TStringList     *ImpModuleList; //Imported modules   list (temporary)
TList           *SegmentList;   //Information about Image Segments
TList           *VmtList;       //VMT list

//Units
int             UnitsNum = 0;
int             UnitSortField = 0; //0 - by address, 1 - by initialization order, 2 - by name
TList           *Units = 0;
TStringList     *PossibleUnitNames = 0;
//Types
TList           *OwnTypeList = 0;

DWORD           CurProcAdr;
int				CurProcSize;
String          SelectedAsmItem;    //Selected item in Asm Listing
DWORD           CurUnitAdr;
DWORD           HInstanceVarAdr;
DWORD           LastTls;            //Last bust index Tls shows how many ThreadVars in program
int             Reserved;
int             LastResStrNo = 0;   //Last ResourceStringNo
DWORD			CtdRegAdr;			//Procedure CtdRegAdr address


//---------------------------------------------------------------------------
#include "TabRTTIs.cpp"
#include "TabStrings.cpp"
#include "TabNames.cpp"
#include "CXrefs.cpp"
//---------------------------------------------------------------------------
//as
//class addresses cache
typedef std::map<const String, DWORD> TClassAdrMap;
static TClassAdrMap classAdrMap;

static void __fastcall ClearClassAdrMap();
//String __fastcall UnmangleName(char* Name);

TFMain_11011981 *FMain_11011981;
//---------------------------------------------------------------------------
__fastcall TFMain_11011981::TFMain_11011981(TComponent* Owner)
    : AnalyzeThread(0), dragdropHelper(Handle), TForm(Owner)
{
}
//---------------------------------------------------------------------------
__fastcall TFMain_11011981::~TFMain_11011981()
{

}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::FormClose(TObject *Sender,
      TCloseAction &Action)
{
    ModalResult = mrCancel;
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::FormKeyDown(TObject *Sender, WORD &Key,
      TShiftState Shift)
{
    switch (Key)
    {
    case 'G':
        GoToAddress();
        break;
    case 'N':
        NamePosition();
        break;
    case 'F':  //CTRL + F (1st search on different areas)
    {
        if (Shift.Contains(ssCtrl))
        {
            switch (WhereSearch)
            {
            case SEARCH_UNITS:
                miSearchUnitClick(Sender);
                break;
            case SEARCH_UNITITEMS:
                miSearchItemClick(Sender);
                break;
            case SEARCH_RTTIS:
                miSearchRTTIClick(Sender);
                break;
            case SEARCH_FORMS:
                miSearchFormClick(Sender);
                break;
            case SEARCH_CLASSVIEWER:
                miSearchVMTClick(Sender);
                break;
            case SEARCH_STRINGS:
                miSearchStringClick(Sender);
                break;
            case SEARCH_NAMES:
                miSearchNameClick(Sender);
                break;            
            //todo rest of locations
            }
        }
        break;
    }
    case VK_F3:  // F3 - (2nd search, continue search with same text)
        switch (WhereSearch)
        {
        case SEARCH_UNITS:
            FindText(UnitsSearchText);
            break;
        case SEARCH_UNITITEMS:
            FindText(UnitItemsSearchText);
            break;
        case SEARCH_RTTIS:
            FindText(RTTIsSearchText);
            break;
        case SEARCH_FORMS:
            FindText(FormsSearchText);
            break;            
        case SEARCH_CLASSVIEWER:
            FindText(VMTsSearchText);
            break;
        case SEARCH_STRINGS:
        	FindText(StringsSearchText);
            break;
        case SEARCH_NAMES:
        	FindText(NamesSearchText);        
            break;            
        }
        break;
    }
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::Units1Click(TObject *Sender)
{
    pcInfo->ActivePage = tsUnits;
    if (lbUnits->CanFocus()) ActiveControl = lbUnits;
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::RTTI1Click(TObject *Sender)
{
    pcInfo->ActivePage = tsRTTIs;
    if (lbRTTIs->CanFocus()) ActiveControl = lbRTTIs;
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::Forms1Click(TObject *Sender)
{
    pcInfo->ActivePage = tsForms;
    if (lbForms->CanFocus()) ActiveControl = lbForms;
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::CodeViewer1Click(TObject *Sender)
{
    pcWorkArea->ActivePage = tsCodeView;
    if (lbCode->CanFocus()) ActiveControl = lbCode;
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::ClassViewer1Click(TObject *Sender)
{
    pcWorkArea->ActivePage = tsClassView;
    if (!rgViewerMode->ItemIndex)
        if (tvClassesFull->CanFocus()) ActiveControl = tvClassesFull;
    else
        if (tvClassesShort->CanFocus()) ActiveControl = tvClassesShort;
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::Strings1Click(TObject *Sender)
{
    pcWorkArea->ActivePage = tsStrings;
    if (lbStrings->CanFocus()) ActiveControl = lbStrings;
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::Names1Click(TObject *Sender)
{
    pcWorkArea->ActivePage = tsNames;
    if (lbNames->CanFocus()) ActiveControl = lbNames;
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::SourceCode1Click(TObject *Sender)
{
    pcWorkArea->ActivePage = tsSourceCode;
    if (lbSourceCode->CanFocus()) ActiveControl = lbSourceCode;
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::miExitClick(TObject *Sender)
{
    Close();
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::Init()
{
    IDPFile = "";
    UnitsNum = 0;
    CurProcAdr = 0;
    CurProcSize = 0;
    SelectedAsmItem = "";
    CurUnitAdr = 0;
    CodeHistoryPtr = -1;
    CodeHistorySize = 0;//HISTORY_CHUNK_LENGTH;
    CodeHistory.Length = CodeHistorySize;
    CodeHistoryMax = CodeHistoryPtr;

	DelphiVersion = -1;
    Caption = "Interactive Delphi Reconstructor (64bit) by crypto and sendersu";

    HInstanceVarAdr = 0xFFFFFFFF;
    LastTls = 0;
    CtdRegAdr = 0;

    WhereSearch = SEARCH_UNITS;
    UnitsSearchFrom = -1;
    UnitsSearchText = "";

    RTTIsSearchFrom = -1;
    RTTIsSearchText = "";

    FormsSearchFrom = -1;
    FormsSearchText = "";

    UnitItemsSearchFrom = -1;
    UnitItemsSearchText = "";

    TreeSearchFrom = 0;
    BranchSearchFrom = 0;
    VMTsSearchText = "";

    StringsSearchFrom = 0;
    StringsSearchText = "";

    NamesSearchFrom = 0;
    NamesSearchText = "";

    //Init Menu
    miLoadFile->Enabled = true;
    miOpenProject->Enabled = true;
    miMRF->Enabled = true;
    miSaveProject->Enabled = false;
    miSaveDelphiProject->Enabled = false;
    miExit->Enabled = true;
    miMapGenerator->Enabled = false;
    miCommentsGenerator->Enabled = false;
    miIDCGenerator->Enabled = false;
    miLister->Enabled = false;
    miClassTreeBuilder->Enabled = false;
    miKBTypeInfo->Enabled = false;
    miCtdPassword->Enabled = false;
    miHex2Double->Enabled = false;

    //Init Units
    lbUnits->Clear();
    miRenameUnit->Enabled = false;
    miSearchUnit->Enabled = false;
    miSortUnits->Enabled = false;
    miCopyList->Enabled = false;
    UnitSortField = 0;
    miSortUnitsByAdr->Checked = true;
    miSortUnitsByOrd->Checked = false;
    miSortUnitsByNam->Checked = false;
    tsUnits->Enabled = false;

    //Init RTTIs
    lbRTTIs->Clear();
    miSearchRTTI->Enabled = false;
    miSortRTTI->Enabled = false;
    RTTISortField = 0;
    miSortRTTIsByAdr->Checked = true;
    miSortRTTIsByKnd->Checked = false;
    miSortRTTIsByNam->Checked = false;
    tsRTTIs->Enabled = false;

    //Init Forms
    lbForms->Clear();
    lbAliases->Clear();
    lClassName->Caption = "";
    cbAliases->Clear();
    rgViewFormAs->ItemIndex = 0;
    tsForms->Enabled = false;

    //Init Code
    lProcName->Caption = "";
    lbCode->Clear();
    lbCode->ScrollWidth = 0;
    miGoTo->Enabled = false;
    miExploreAdr->Enabled = false;
    miName->Enabled = false;
    miViewProto->Enabled = false;
    miEditFunctionC->Enabled = false;
    miXRefs->Enabled = false;
    miSwitchFlag->Enabled = false;
    bEP->Enabled = false;
    bDecompile->Enabled = false;
    bCodePrev->Enabled = false;
    bCodeNext->Enabled = false;
    tsCodeView->Enabled = false;
    lbCXrefs->Clear();
    lbCXrefs->Visible = true;

    //Init Strings
    lbStrings->Clear();
    miSearchString->Enabled = false;
    tsStrings->Enabled = false;
    //Init Names
    lbNames->Clear();
    tsNames->Enabled = false;

    //Xrefs
    lbSXrefs->Clear();
    lbSXrefs->Visible = true;

    //Init Unit Items
    lbUnitItems->Clear();
    lbUnitItems->ScrollWidth = 0;
    miEditFunctionI->Enabled = false;
    miFuzzyScanKB->Enabled = false;
    miSearchItem->Enabled = false;

    //Init ClassViewer
    ClassTreeDone = false;
    tvClassesFull->Items->Clear();
    tvClassesShort->Items->Clear();
    tvClassesShort->BringToFront();
    rgViewerMode->ItemIndex = 1;    //Short View
    tsClassView->Enabled = false;

    ClearTreeNodeMap();
    ClearClassAdrMap();

    Update();
    Sleep(0);

    ProjectLoaded = false;
    ProjectModified = false;
    UserKnowledgeBase = false;
    SourceIsLibrary = false;
}
//---------------------------------------------------------------------------
PImportNameRec __fastcall TFMain_11011981::GetImportRec(DWORD adr)
{
    for (int n = 0; n < ImpFuncList->Count; n++)
    {
        PImportNameRec recI = (PImportNameRec)ImpFuncList->Items[n];
        if (adr == recI->address)
            return recI;
    }
    return 0;
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::FindExports()
{
    int     pos;

    for (int i = 0; i < ExpFuncList->Count; i++)
    {
        PExportNameRec recE = (PExportNameRec)ExpFuncList->Items[i];
        DWORD Adr = recE->address;
        if (IsValidImageAdr(Adr) && (pos = Adr2Pos(Adr)) != -1)
        {
            PInfoRec recN = new InfoRec(pos, ikRefine);
            recN->SetName(recE->name);
            recN->procInfo->flags = 3;     //stdcall
            //idr.SetInfosAt(pos, recN);
            idr.SetFlag(cfProcStart | cfExport, pos);
        }
    }
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::FindImports()
{
    char        *b, *e;
    int         pos;
    String      name;

    for (int i = 0; i < TotalSize - 6; i++)
    {
        if (Code[i] == 0xFF && Code[i + 1] == 0x25)
        {
            DWORD ofs = *((DWORD*)(Code + i + 2));
            PImportNameRec recI = GetImportRec(CodeBase + i + 6 + ofs);
            if (recI)
            {
                //name = UnmangleName(recI->name);
                if (!idr.HasInfosAt(i))
                {
                    PInfoRec recN = new InfoRec(i, ikRefine);
                    recN->procInfo->procSize = 6;
                    idr.SetFlag(cfProcStart, i);
                    idr.SetFlag(cfProcEnd, i + 6);
                    
                    if (recI->name.Pos("@Initialization$") || recI->name.Pos("@Finalization$"))
                    {
                        recN->SetName(recI->module + "." + recI->name);
                    }
                    else
                    {
                        b = strchr(recI->name.c_str() + 1, '@');
                        if (b)
                        {
                            e = strchr(b + 1, '$');
                            if (e)
                            {
                                if (*(e - 1) != '@')
                                    recN->SetName(String(b + 1, e - b - 1));
                                else
                                    recN->SetName(String(b + 1, e - b - 2));
                                if (recI->name.Pos("$bctr$"))
                                {
                                    recN->ConcatName("@Create");
                                    recN->kind = ikConstructor;
                                }
                                else if (recI->name.Pos("$bdtr$"))
                                {
                                    recN->ConcatName("@Destroy");
                                    recN->kind = ikDestructor;
                                }
                                pos = recN->GetName().Pos("@");
                                if (pos > 1) recN->GetName()[pos] = '.';
                            }
                        }
                        else
                            recN->SetName(recI->module + "." + recI->name);
                    }
                    for (int n = 0; n < SYSPROCSNUM; n++)
                    {
                        if (recI->name.Pos(SysProcs[n].name))
                        {
                            SysProcs[n].impAdr = Pos2Adr(i);
                            break;
                        }
                    }
                    idr.SetFlag(cfImport, i);
                }
                idr.SetFlags(cfCode, i, 6);
            }
        }
    }
}
//---------------------------------------------------------------------------
static int DelphiVersions[] = {2012, 2013, 2014, 2015, 2016};  //more to be added!!! :)
int __fastcall TFMain_11011981::GetDelphiVersion()
{
    WORD            moduleID;
    int             idx, pos;
    String          KBFileName;
    MKnowledgeBase	SysKB;
    MProcInfo       aInfo;
    MProcInfo*      pInfo = &aInfo;

    KBFileName = AppDir + "syskb2014.bin";
    if (SysKB.Open(KBFileName.c_str()))
    {
        moduleID = SysKB.GetModuleID("System");
        if (moduleID != 0xFFFF)
        {
            //Find index of function "StringCopy" in this module
            //idx = SysKB.GetProcIdx(moduleID, "StringCopy");
            idx = SysKB.GetProcIdx(moduleID, "FRaiseExcept");
            if (idx != -1)
            {
                pInfo = SysKB.GetProcInfo(SysKB.ProcOffsets[idx].NamId, INFO_DUMP, &aInfo);
                pos = SysKB.ScanCode(Code, idr.Flags, CodeSize, pInfo);
                if (pos != -1)
                {
                    SysKB.Close();
                    return 2014;
                }
            }
        }
        SysKB.Close();
    }
    KBFileName = AppDir + "syskb2013.bin";
    if (SysKB.Open(KBFileName.c_str()))
    {
        moduleID = SysKB.GetModuleID("System");
        if (moduleID != 0xFFFF)
        {
            //Find index of function "@FinalizeResStrings" in this module
            //idx = SysKB.GetProcIdx(moduleID, "@FinalizeResStrings");
            idx = SysKB.GetProcIdx(moduleID, "RaiseOverflowException");
            if (idx != -1)
            {
                pInfo = SysKB.GetProcInfo(SysKB.ProcOffsets[idx].NamId, INFO_DUMP, &aInfo);
                pos = SysKB.ScanCode(Code, idr.Flags, CodeSize, pInfo);
                if (pos != -1)
                {
                    SysKB.Close();
                    return 2013;
                }
            }
        }
        SysKB.Close();
    }

    KBFileName = AppDir + "syskb2012.bin";
    if (SysKB.Open(KBFileName.c_str()))
    {
        moduleID = SysKB.GetModuleID("System");
        if (moduleID != 0xFFFF)
        {
            //Find index of function "@InitializeControlWord" in this module
            idx = SysKB.GetProcIdx(moduleID, "@InitializeControlWord");
            if (idx != -1)
            {
                pInfo = SysKB.GetProcInfo(SysKB.ProcOffsets[idx].NamId, INFO_DUMP, &aInfo);
                pos = SysKB.ScanCode(Code, idr.Flags, CodeSize, pInfo);
                if (pos != -1)
                {
                    SysKB.Close();
                    return 2012;
                }
            }
        }
        SysKB.Close();
    }
    //Here we failed to find the version.....sorry
    return -1;
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::InitSysProcs()
{
    int         Idx, pos;
    MProcInfo   aInfo, *pInfo;

    SysProcsNum = 0;
    WORD moduleID = KnowledgeBase.GetModuleID("System");
    for (int n = 0; n < SYSPROCSNUM; n++)
    {
        Idx = KnowledgeBase.GetProcIdx(moduleID, SysProcs[n].name);
        if (Idx != -1)
        {
            Idx = KnowledgeBase.ProcOffsets[Idx].NamId;
            if (!KnowledgeBase.IsUsedProc(Idx))
            {
                pInfo = KnowledgeBase.GetProcInfo(Idx, INFO_DUMP, &aInfo);
                if (SysProcs[n].impAdr)
                {
                    StrapProc(Adr2Pos(SysProcs[n].impAdr), Idx, pInfo, false, 6);
                }
                else
                {
                    pos = KnowledgeBase.ScanCode(Code, idr.Flags, CodeSize, pInfo);
                    if (pos != -1)
                    {
                        PInfoRec recN = new InfoRec(pos, ikRefine);
                        recN->SetName(SysProcs[n].name);
                        StrapProc(pos, Idx, pInfo, true, pInfo->DumpSz);
                    }
                }
            }
        }
        SysProcsNum++;
    }
    moduleID = KnowledgeBase.GetModuleID("SysInit");
    for (int n = 0; n < SYSINITPROCSNUM; n++)
    {
        Idx = KnowledgeBase.GetProcIdx(moduleID, SysInitProcs[n].name);
        if (Idx != -1)
        {
            Idx = KnowledgeBase.ProcOffsets[Idx].NamId;
            if (!KnowledgeBase.IsUsedProc(Idx))
            {
                pInfo = KnowledgeBase.GetProcInfo(Idx, INFO_DUMP, &aInfo);
                if (SysInitProcs[n].impAdr)
                {
                    StrapProc(Adr2Pos(SysInitProcs[n].impAdr), Idx, pInfo, false, 6);
                }
                pos = KnowledgeBase.ScanCode(Code, idr.Flags, CodeSize, pInfo);
                if (pos != -1)
                {
                    PInfoRec recN = new InfoRec(pos, ikRefine);
                    recN->SetName(SysInitProcs[n].name);
                    StrapProc(pos, Idx, pInfo, true, pInfo->DumpSz);
                    if (n == 1) SourceIsLibrary = true;
                }
            }
        }
        SysProcsNum++;
    }
}
//---------------------------------------------------------------------------
DWORD __fastcall FollowInstructions(DWORD fromAdr, DWORD toAdr)
{
    int         instrLen;
    int         fromPos = Adr2Pos(fromAdr);
    int         curPos = fromPos;
    DWORD       curAdr = fromAdr;
    DISINFO     DisInfo;
    
    while (1)
    {
        if (curAdr >= toAdr) break;
        if (idr.IsFlagSet(cfInstruction, curPos)) break;
        instrLen = GetDisasm().Disassemble(Code + curPos, (__int64)curAdr, &DisInfo, 0);
        if (!instrLen) break;
        idr.SetFlag(cfInstruction, curPos);
    }
    return curAdr;
}
//---------------------------------------------------------------------------
ULONGLONG __fastcall TFMain_11011981::EvaluateInitTable(BYTE* Data, DWORD Size, ULONGLONG Base)
{
    LONGLONG    i, num, pos, unitsPos = 0, n;
    ULONGLONG   initTable, iniAdr, finAdr, maxAdr = 0;

    maxAdr = 0;
    for (i = 0; i < ((Size - 0x28) & (-8)); i += 8)
    {
        initTable = *((ULONGLONG*)(Data + i));
        if (initTable == Base + i + 0x28)
        {
            num = *((ULONGLONG*)(Data + i - 8));
            if (num <= 0 || num > 10000) continue;

        	pos = unitsPos = i + 0x28;
            for (n = 0; n < num; n++, pos += 16)
            {
                iniAdr = *((ULONGLONG*)(Data + pos));
                if (iniAdr)
                {
                    if (iniAdr < Base || iniAdr >= Base + Size)
                    {
                        unitsPos = 0;
                        break;
                    }
                    else if (iniAdr > maxAdr)
                    {
                        if (*((ULONGLONG*)(Data + Adr2Pos(iniAdr)))) maxAdr = iniAdr;
                    }
                }
                finAdr = *((ULONGLONG*)(Data + pos + 8));
                if (finAdr)
                {
                    if (finAdr < Base || finAdr >= Base + Size)
                    {
                        unitsPos = 0;
                        break;
                    }
                    else if (finAdr > maxAdr)
                    {
                        if (*((DWORD*)(Data + Adr2Pos(finAdr)))) maxAdr = finAdr;
                    }
                }
            }
            if (unitsPos) break;
        }
    }
    if (unitsPos) return initTable - 0x30;
    return 0;
}
//---------------------------------------------------------------------------
int __fastcall TFMain_11011981::GetUnits(String dprName)
{
    BYTE        len;
    char        *b, *e;
	int         n, i, no, unitsPos, start, spos, pos, iniProcSize, finProcSize, unitsNum;
    int         typesNum, punitsNum;
	DWORD       unitsTab, unitsTabEnd, typesTable, punitsTable, iniAdr, finAdr, toAdr;
	PUnitRec    recU;
    PInfoRec    recN;

    unitsNum = *((LONGLONG*)(Image + Adr2Pos(InitTable)));
    unitsTab = *((LONGLONG*)(Image + Adr2Pos(InitTable + 8)));
    unitsPos = Adr2Pos(unitsTab);
    unitsTabEnd = unitsTab + 16 * unitsNum;
    idr.SetFlags(cfData, unitsPos, 16 * unitsNum);
    typesNum = *((LONGLONG*)(Image + Adr2Pos(InitTable + 0x10)));
    typesTable = *((ULONGLONG*)(Image + Adr2Pos(InitTable + 0x18)));
    idr.SetFlags(cfData, Adr2Pos(typesTable), 8*typesNum);
    punitsNum = *((LONGLONG*)(Image + Adr2Pos(InitTable + 0x20)));
    punitsTable = *((ULONGLONG*)(Image + Adr2Pos(InitTable + 0x28)));
    spos = pos = Adr2Pos(punitsTable);
    for (i = 0; i < punitsNum; i++)
    {
        len = *(Image + pos);
        PossibleUnitNames->Add(String((char*)(Image + pos + 1), len));
        pos += len + 1;
    }
    idr.SetFlags(cfData, Adr2Pos(punitsTable), pos - spos);

    for (i = 0, no = 1; i < unitsNum; i++, unitsPos += 16)
    {
        iniAdr = *((ULONGLONG*)(Image + unitsPos));
        finAdr = *((ULONGLONG*)(Image + unitsPos + 8));

        if (!iniAdr && !finAdr) continue;

        if (iniAdr && *((ULONGLONG*)(Image + Adr2Pos(iniAdr))) == 0) continue;
        if (finAdr && *((ULONGLONG*)(Image + Adr2Pos(finAdr))) == 0) continue;

        //MAY BE REPEATED ADRESSES!!!
        bool found = false;
        for (n = 0; n < Units->Count; n++)
        {
            recU = (PUnitRec)Units->Items[n];
            if (recU->iniadr == iniAdr && recU->finadr == finAdr)
            {
                found = true;
                break;
            }
        }
        if (found) continue;

        if (iniAdr)
        	iniProcSize = EstimateProcSize(iniAdr);
        else
        	iniProcSize = 0;

        if (finAdr)
        	finProcSize = EstimateProcSize(finAdr);
        else
        	finProcSize = 0;

        toAdr = 0;
        if (iniAdr && iniAdr < unitsTabEnd)
        {
            if (iniAdr >= finAdr + finProcSize)
                toAdr = (iniAdr + iniProcSize + 7) & (-8);
            if (finAdr >= iniAdr + iniProcSize)
                toAdr = (finAdr + finProcSize + 7) & (-8);
        }
        else if (finAdr)
        {
            toAdr = (finAdr + finProcSize + 7) & (-8);
        }

        if (!toAdr)
        {
            if (Units->Count > 0) continue;
            toAdr = CodeBase + CodeSize;
        }

        recU = new UnitRec;
        recU->trivial = false;
        recU->trivialIni = true;
        recU->trivialFin = true;
        recU->kb = false;
        recU->names = new TStringList;

        recU->fromAdr = 0;
        recU->toAdr = toAdr;
        recU->matchedPercent = 0.0;
        recU->iniOrder = no; no++;

        recU->finadr = finAdr;
        recU->finSize = finProcSize;
        recU->iniadr = iniAdr;
        recU->iniSize = iniProcSize;

        if (iniAdr)
        {
            pos = Adr2Pos(iniAdr);
	        //Check trivial initialization
        	if (iniProcSize > 15) recU->trivialIni = false;
            //idr.SetFlag(cfProcStart, pos);
            //idr.SetFlag(cfProcEnd, pos + iniProcSize);
            recN = GetInfoRec(iniAdr);
            if (!recN) recN = new InfoRec(pos, ikProc);
            recN->procInfo->procSize = iniProcSize;
        }
        if (finAdr)
        {
            pos = Adr2Pos(finAdr);
	        //Check trivial finalization
        	if (finProcSize > 15) recU->trivialFin = false;
            //idr.SetFlag(cfProcStart, pos);
            //idr.SetFlag(cfProcEnd, pos + finProcSize);
            recN = GetInfoRec(finAdr);
            if (!recN) recN = new InfoRec(pos, ikProc);
            recN->procInfo->procSize = finProcSize;
            //import?
            if (idr.IsFlagSet(cfImport, pos))
            {
                b = strchr(recN->GetName().c_str(), '@');
                if (b)
                {
                    e = strchr(b + 1, '@');
                    if (e) SetUnitName(recU, String(b + 1, e - b - 1));
                }
            }
        }
        Units->Add((void*)recU);
    }

    Units->Sort(&SortUnitsByAdr);

    start = CodeBase;
    unitsNum = Units->Count;
	for (i = 0; i < unitsNum; i++)
    {
    	recU = (PUnitRec)Units->Items[i];
        recU->fromAdr = start;
        if (recU->toAdr) start = recU->toAdr;
        //Is unit trivial?
        if (recU->trivialIni && recU->trivialFin)
        {
            int isize = (recU->iniSize + 7) & (-8);
            int fsize = (recU->finSize + 7) & (-8);
            if (isize + fsize == recU->toAdr - recU->fromAdr) recU->trivial = true;
        }
        //Last unit has program name and toAdr = initTable
        if (i == unitsNum - 1)
        {
            recU->toAdr = InitTable;
            SetUnitName(recU, dprName);
        }
    }
    return unitsNum;
}
//---------------------------------------------------------------------------
int __fastcall TFMain_11011981::GetBCBUnits(String dprName)
{
    int         n, pos, curPos, instrLen, iniNum, finNum, unitsNum, no, _mnemIdx;
    DWORD       adr, curAdr, modTable, iniTable, iniTableEnd, finTable, finTableEnd, fromAdr, toAdr;
    PUnitRec    recU;
    PInfoRec    recN;
    DISINFO     disInfo;

    //EP: jmp @1
    curAdr = EP; curPos = Adr2Pos(curAdr);
    instrLen = GetDisasm().Disassemble(Code + curPos, (__int64)curAdr, &disInfo, 0);
    _mnemIdx = disInfo.MnemIdx;
    if (_mnemIdx == IDX_JMP)
    {
        curAdr = disInfo.Immediate; curPos = Adr2Pos(curAdr);
        while (1)
        {
            instrLen = GetDisasm().Disassemble(Code + curPos, (__int64)curAdr, &disInfo, 0);
            _mnemIdx = disInfo.MnemIdx;
            if (_mnemIdx == IDX_JMP) break;
            if (_mnemIdx == IDX_PUSH && disInfo.OpType[0] == otIMM && disInfo.Immediate)
            {
                modTable = disInfo.Immediate;
                if (IsValidImageAdr(modTable))
                {
                    pos = Adr2Pos(modTable);
                    iniTable = *((DWORD*)(Image + pos));
                    iniTableEnd = *((DWORD*)(Image + pos + 4));
                    finTable = *((DWORD*)(Image + pos + 8));
                    finTableEnd = *((DWORD*)(Image + pos + 12));
                    for (n = 16; n < 32; n += 4)
                    {
                        adr = *((DWORD*)(Image + pos + n));
                        if (IsValidImageAdr(adr))
                        {
                            pos = Adr2Pos(adr);
                            idr.SetFlag(cfProcStart, pos);
                            recN = GetInfoRec(adr);
                            if (!recN) recN = new InfoRec(pos, ikProc);
                            recN->SetName("WinMain");
                            break;
                        }
                    }

                    iniNum = (iniTableEnd - iniTable) / 6;
                    idr.SetFlags(cfData, Adr2Pos(iniTable), iniTableEnd - iniTable);
                    finNum = (finTableEnd - finTable) / 6;
                    idr.SetFlags(cfData, Adr2Pos(finTable), finTableEnd - finTable);

                    TStringList* list = new TStringList;
                    list->Sorted = false;
                    list->Duplicates = dupIgnore;
                    if (iniNum > finNum)
                    {
                        pos = Adr2Pos(iniTable);
                        for (n = 0; n < iniNum; n++)
                        {
                            adr = *((DWORD*)(Image + pos + 2));
                            pos += 6;
                            list->Add(Val2Str8(adr));
                        }
                    }
                    else
                    {
                        pos = Adr2Pos(finTable);
                        for (n = 0; n < finNum; n++)
                        {
                            adr = *((DWORD*)(Image + pos + 2));
                            pos += 6;
                            list->Add(Val2Str8(adr));
                        }
                    }
                    list->Sort();
                    fromAdr = CodeBase; no = 1;
                    for (n = 0; n < list->Count; n++)
                    {
                        recU = new UnitRec;
                        recU->trivial = false;
                        recU->trivialIni = true;
                        recU->trivialFin = true;
                        recU->kb = false;
                        recU->names = new TStringList;

                        recU->matchedPercent = 0.0;
                        recU->iniOrder = no; no++;

                        toAdr = StrToInt(String("$") + list->Strings[n]);
                        recU->finadr = 0;
                        recU->finSize = 0;
                        recU->iniadr = toAdr;
                        recU->iniSize = 0;

                        recU->fromAdr = fromAdr;
                        recU->toAdr = toAdr;
                        Units->Add((void*)recU);

                        fromAdr = toAdr;
                        if (n == list->Count - 1) SetUnitName(recU, dprName);
                    }
                    delete list;
                    Units->Sort(&SortUnitsByAdr);
                    return Units->Count;
                }
            }
            curAdr += instrLen; curPos += instrLen;
        }
    }
    return 0;
}
//---------------------------------------------------------------------------
//-1 - not Code
//0 - possible Code
//1 - Code
int __fastcall Idr64Manager::IsValidCode(DWORD fromAdr)
{
    BYTE        op;
    int         firstPushReg, lastPopReg;
    int         firstPushPos, lastPopPos;
    int         row, num, instrLen, instrLen1, instrLen2, _mnemIdx;
    int         fromPos;
    int         curPos;
    DWORD       curAdr;
    DWORD       lastAdr = 0;
    DWORD       Adr, Adr1, Pos, lastMovAdr = 0;
    PInfoRec    recN;
    DISINFO     DisInfo;

    fromPos = Adr2Pos(fromAdr);
    if (fromPos < 0) return -1;

    if (fromAdr > EP) return -1;
    //DISPLAY
    if (!stricmp(Code + fromPos, "DISPLAY")) return -1;

    //recN = GetInfoRec(fromAdr);
    int outRows = MAX_DISASSEMBLE;
    if (idr.IsFlagSet(cfImport, fromPos)) outRows = 1;

    firstPushReg = lastPopReg = -1;
    firstPushPos = lastPopPos = -1;
    curPos = fromPos; curAdr = fromAdr;

    for (row = 0; row < outRows; row++)
    {
        //Exception table
        if (!IsValidImageAdr(curAdr)) return -1;

        BYTE b1 = Code[curPos];
        BYTE b2 = Code[curPos + 1];
        if (!b1 && !b2 && !lastAdr) return -1;

        instrLen = GetDisasm().Disassemble(Code + curPos, (__int64)curAdr, &DisInfo, 0);
        //if (!instrLen) return -1;
        if (!instrLen)//????????
        {
            curPos++; curAdr++;
            continue;
        }
        _mnemIdx = DisInfo.MnemIdx;
        if (_mnemIdx == IDX_ARPL || _mnemIdx == IDX_OUT  || _mnemIdx == IDX_IN)
        {
            return -1;
        }
        op = GetDisasm().GetOp(DisInfo.MnemIdx);

        if (op == OP_JMP)
        {
            if (curAdr == fromAdr) break;
            if (DisInfo.OpType[0] == otMEM)
            {
                if (Adr2Pos(DisInfo.Offset) < 0 && (!lastAdr || curAdr == lastAdr)) break;
            }
            if (DisInfo.OpType[0] == otIMM)
            {
                Adr = DisInfo.Immediate; Pos = Adr2Pos(Adr);
                if (Pos < 0 && (!lastAdr || curAdr == lastAdr)) break;
                if (GetSegmentNo(Adr) != 0 && GetSegmentNo(fromAdr) != GetSegmentNo(Adr) && (!lastAdr || curAdr == lastAdr)) break;
                if (Adr < fromAdr && (!lastAdr || curAdr == lastAdr)) break;
                curAdr = Adr; curPos = Pos;
                continue;
            }
        }

        //Mark push or pop
        if (op == OP_PUSH)
        {
            //If first instruction is not push reg
            if (!row && DisInfo.OpType[0] != otREG) return -1;
            if (DisInfo.OpType[0] == otREG && firstPushReg == -1)
            {
                firstPushReg = DisInfo.OpRegIdx[0];
                firstPushPos = curPos;
            }
        }
        else if (op == OP_POP)
        {
            if (DisInfo.OpType[0] == otREG)
            {
                lastPopReg = DisInfo.OpRegIdx[0];
                lastPopPos = curPos;
            }
        }

        //Look at first instruction
        if (!row)
        {
            //Branch or ret with operand
            if (DisInfo.Ret && DisInfo.OpNum >= 1) return -1;
            if (DisInfo.Branch) return -1;
            if (_mnemIdx == IDX_BOUND || _mnemIdx == IDX_RETF || _mnemIdx == IDX_POP ||
                _mnemIdx == IDX_AAA || _mnemIdx == IDX_ADC || _mnemIdx == IDX_SBB ||
                _mnemIdx == IDX_RCL || _mnemIdx == IDX_RCR || _mnemIdx == IDX_CLC ||
                _mnemIdx == IDX_STC)
                return -1;
        }
        //Если в позиции встретился уже определенный ранее код, выходим
        for (int k = 0; k < instrLen; k++)
        {
            if (idr.IsFlagSet(cfProcStart, curPos + k) || idr.IsFlagSet(cfCode, curPos + k))
                return -1;
        }

        if (curAdr >= lastAdr) lastAdr = 0;
        //Proc end
        if (DisInfo.Ret && (!lastAdr || curAdr == lastAdr))
        {
            //Standard frame
            if (Code[fromPos] == 0x55 && Code[fromPos + 1] == 0x8B && Code[fromPos + 2] == 0xEC)
                break;
            if (firstPushReg == lastPopReg && firstPushPos == fromPos && lastPopPos == curPos - 1)
                break;
            return 0;
        }

        if (op == OP_MOV) lastMovAdr = DisInfo.Offset;

        if (b1 == 0xEB ||				 //short relative abs jmp or cond jmp
        	(b1 >= 0x70 && b1 <= 0x7F) ||
            (b1 == 0xF && b2 >= 0x80 && b2 <= 0x8F))
        {
            Adr = DisInfo.Immediate;
            if (!IsValidImageAdr(Adr)) return -1;
            if (IsValidCodeAdr(Adr))
            {
                if (Adr >= fromAdr && Adr > lastAdr) lastAdr = Adr;
            }
            curPos += instrLen; curAdr += instrLen;
            continue;
        }
        if (b1 == 0xE9)    //relative abs jmp or cond jmp
        {
            Adr = DisInfo.Immediate;
            if (!IsValidImageAdr(Adr)) return -1;
            if (IsValidCodeAdr(Adr))
            {
                recN = GetInfoRec(Adr);
                if (!recN && Adr >= fromAdr && Adr > lastAdr) lastAdr = Adr;
            }
            curPos += instrLen; curAdr += instrLen;
            continue;
        }
        curPos += instrLen; curAdr += instrLen;
    }
    return 1;
}
//---------------------------------------------------------------------------
//Sort VmtList by height and vmtAdr
int __fastcall SortPairsCmpFunction(void *item1, void *item2)
{
    PVmtListRec rec1 = (PVmtListRec)item1;
    PVmtListRec rec2 = (PVmtListRec)item2;

    if (rec1->height > rec2->height) return 1;
    if (rec1->height < rec2->height) return -1;
    if (rec1->vmtAdr > rec2->vmtAdr) return 1;
    if (rec1->vmtAdr < rec2->vmtAdr) return -1;
    return 0;
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::FillVmtList()
{
    VmtList->Clear();

    for (int n = 0; n < TotalSize; n++)
    {
        PInfoRec recN = GetInfoRec(Pos2Adr(n));
    	if (recN && recN->kind == ikVMT && recN->HasName())
        {
            PVmtListRec recV = new VmtListRec;
            recV->height = GetClassHeight(Pos2Adr(n));
            recV->vmtAdr = Pos2Adr(n);
            recV->vmtName = recN->GetName();
            VmtList->Add((void*)recV);
        }
    }
    VmtList->Sort(SortPairsCmpFunction);
}
//---------------------------------------------------------------------------
//Return virtual method offset of procedure with address procAdr
int __fastcall TFMain_11011981::GetMethodOfs(PInfoRec rec, DWORD procAdr)
{
    if (rec && rec->vmtInfo->methods)
    {
        for (int m = 0; m < rec->vmtInfo->methods->Count; m++)
        {
            PMethodRec recM = (PMethodRec)rec->vmtInfo->methods->Items[m];
            if (recM->kind == 'V' && recM->address == procAdr) return recM->id;
        }
    }
    return -1;
}
//---------------------------------------------------------------------------
bool __fastcall IsOwnVirtualMethod(DWORD vmtAdr, DWORD procAdr)
{
    DWORD parentAdr = GetParentAdr(vmtAdr);
    if (!parentAdr) return true;
    DWORD stopAt = GetStopAt(parentAdr - Vmt.SelfPtr);
    if (vmtAdr == stopAt) return false;

    int pos = Adr2Pos(parentAdr) + Vmt.Parent + 4;

    for (int m = Vmt.Parent + 4;; m += 4, pos += 4)
    {
        if (Pos2Adr(pos) == stopAt) break;

        if (*((DWORD*)(Code + pos)) == procAdr) return false;
    }
    return true;
}
//---------------------------------------------------------------------------
void __fastcall ClearClassAdrMap()
{
    classAdrMap.clear();
}
//---------------------------------------------------------------------------
DWORD __fastcall FindClassAdrByName(const String& AName)
{
    TClassAdrMap::const_iterator it = classAdrMap.find(AName);
    if (it != classAdrMap.end()) return it->second;

    return 0;
}
//---------------------------------------------------------------------------
void __fastcall AddClassAdr(DWORD Adr, const String& AName)
{
    classAdrMap[AName] = Adr;
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::FormCreate(TObject *Sender)
{
    ParseCommandLineArgs();
    
    AppDir = ExtractFilePath(Application->ExeName);
    if (AppDir[AppDir.Length()] != '\\') AppDir += "\\";
    Application->HelpFile = AppDir + "idr.chm";
    IniFileRead();

    SegmentList = new TList;
    ExpFuncList = new TList;
    ImpFuncList = new TList;
    ImpModuleList = new TStringList;
    VmtList = new TList;
    //ResInfo = new TResourceInfo;
    Units = new TList;
    PossibleUnitNames = new TStringList;
    OwnTypeList = new TList;
    UnitsSearchList = new TStringList;
    RTTIsSearchList = new TStringList;
    UnitItemsSearchList = new TStringList;
    VMTsSearchList = new TStringList;
    FormsSearchList = new TStringList;
    StringsSearchList = new TStringList;
    NamesSearchList = new TStringList;

    if (!GetDisasm().Init())
    {
        LogMessage("Cannot initialize Disasm, stop work", MB_ICONERROR);
        SourceFile = "";
        Application->Terminate();
        return;
    }

    miDelphiXE2->Enabled = FileExists(AppDir + "kb2012.bin");
    miDelphiXE3->Enabled = FileExists(AppDir + "kb2013.bin");
    miDelphiXE4->Enabled = FileExists(AppDir + "kb2014.bin");
    
    Init();

    lbUnits->Canvas->Font->Assign(lbUnits->Font);
    lbRTTIs->Canvas->Font->Assign(lbRTTIs->Font);
    lbForms->Canvas->Font->Assign(lbForms->Font);
    lbCode->Canvas->Font->Assign(lbCode->Font);
    lbUnitItems->Canvas->Font->Assign(lbUnitItems->Font);

    lbCXrefs->Canvas->Font->Assign(lbCXrefs->Font);
    lbCXrefs->Width = lbCXrefs->Canvas->TextWidth("T")*14;
    ShowCXrefs->Width = lbCXrefs->Width;

    lbSXrefs->Canvas->Font->Assign(lbSXrefs->Font);
    lbSXrefs->Width = lbSXrefs->Canvas->TextWidth("T")*14;
    ShowSXrefs->Width = lbSXrefs->Width;

    lbNXrefs->Canvas->Font->Assign(lbNXrefs->Font);
    lbNXrefs->Width = lbNXrefs->Canvas->TextWidth("T")*14;
    ShowNXrefs->Width = lbNXrefs->Width;

    ScaleForm(this);
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::FormDestroy(TObject *Sender)
{
    CloseProject();

    delete SegmentList;
    delete ExpFuncList;
    delete ImpFuncList;
    delete ImpModuleList;
    delete VmtList;
    //delete ResInfo;
    delete OwnTypeList;
    delete UnitsSearchList;
    delete RTTIsSearchList;
    delete UnitItemsSearchList;
    delete VMTsSearchList;
    delete FormsSearchList;
    delete StringsSearchList;
    delete NamesSearchList;

    CleanupList<PUnitRec>(Units);
    
    delete PossibleUnitNames;
}
//---------------------------------------------------------------------------
String __fastcall TFMain_11011981::GetFilenameFromLink(String LinkName)
{
    String          result = "";
    IPersistFile*   ppf;
    IShellLink*     pshl;
    WIN32_FIND_DATA wfd;

    //Initialize COM-library
    CoInitialize(NULL);
    //Create COM-object and get pointer to interface IPersistFile
    CoCreateInstance(CLSID_ShellLink, 0, CLSCTX_INPROC_SERVER, IID_IPersistFile, (void**)(&ppf));
    //Load Shortcut
    wchar_t* temp = new wchar_t[MAX_PATH];
    StringToWideChar(LinkName, temp, MAX_PATH);
    ppf->Load(temp, STGM_READ);
    delete[] temp;

    //Get pointer to IShellLink
    ppf->QueryInterface(IID_IShellLink, (void**)(&pshl));
    //Find Object shortcut points to
    pshl->Resolve(0, SLR_ANY_MATCH | SLR_NO_UI);
    //Get Object name
    char* targetName = new char[MAX_PATH];
    pshl->GetPath(targetName, MAX_PATH, &wfd, 0);
    result = String(targetName);
    delete[] targetName;

    pshl->Release();
    ppf->Release();

    CoFreeUnusedLibraries();
    CoUninitialize();
    
    return result;
}
//---------------------------------------------------------------------------

void __fastcall TFMain_11011981::ParseCommandLineArgs()
{
    quietMode = false;

    //start from 1st real param (0 is my exe name)
    for (int i = 1; i <= ParamCount(); ++i)
    {
        String curParam = ParamStr(i);
        if (curParam == "-q" || curParam == "/q")
        {
            quietMode = true;
            continue;
        }

        SourceFile = curParam;
    }
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::FormShow(TObject *Sender)
{
    if (SourceFile == "") return;
    
    String FileName = SourceFile;
    const String fileExtension = ExtractFileExt(FileName);

    if (SameText(fileExtension, ".lnk"))
    {
        FileName = GetFilenameFromLink(FileName);
    }

    if (IsExe(FileName))
    {
        LoadDelphiFile1(FileName, DELHPI_VERSION_AUTO, true, true);
    }
    else if (IsIdp(FileName))
    {
        OpenProject(FileName);
    }
    else
    {
        //ShowMessage("File " + FileName + " is not executable or IDR project file");
        LogMessage("File " + FileName + " is not executable or IDR project file", MB_ICONWARNING);
    }
}
//---------------------------------------------------------------------------
/*
void __fastcall TFMain_11011981::ScanImports()
{
    String  name;
    int *cnt = new int[KnowledgeBase.ModuleCount];
    //Попробуем сканировать интервал адресов безымянных модулей по именам импортируемых функций
    for (int m = 0; m < UnitsNum; m++)
    {
        PUnitRec recU = (PUnitRec)Units->Items[m];
        if (!recU->names->Count)
        {
            memset(cnt, 0, KnowledgeBase.ModuleCount*sizeof(int));

            int fromPos = Adr2Pos(recU->fromAdr);
            int toPos = Adr2Pos(recU->toAdr);
            int totcnt = 0;

            for (int n = fromPos; n < toPos; n++)
            {
                PInfoRec recN = GetInfoRec(Pos2Adr(n));
                if (recN && idr.IsFlagSet(cfImport, n))
                {
                    name = ExtractProcName(recN->name);
                    KnowledgeBase.GetModuleIdsByProcName(name.c_str());
                    for (int k = 0;;k++)
                    {
                        if (KnowledgeBase.Mods[k] == 0xFFFF) break;
                        cnt[KnowledgeBase.Mods[k]]++;
                        totcnt++;
                    }
                }
            }

            if (totcnt)
            {
                int num = 0; WORD id;
                for (int k = 0; k < KnowledgeBase.ModuleCount; k++)
                {
                    if (cnt[k] == totcnt)
                    {
                        id = k;
                        num++;
                    }
                }
                DWORD iniadr; PInfoRec recN;
                //Если все импорты нашлись только в одном юните, значит это он и есть
                if (num == 1)
                {
                    name = KnowledgeBase.GetModuleName(id);
                    if (recU->names->IndexOf(name) == -1)
                    {
                        recU->kb = true;
                        SetUnitName(recU, name);
                    }
                }
                //Если в нескольких, попробуем поискать процедуры по cfProcStart (если таковые имеются)
                else
                {
                    for (int k = 0; k < KnowledgeBase.ModuleCount; k++)
                    {
                        if (cnt[k] == totcnt)
                        {
                            id = k;
                            int FirstProcIdx, LastProcIdx;
                            if (!KnowledgeBase.GetProcIdxs(id, &FirstProcIdx, &LastProcIdx)) continue;

                            for (int m = fromPos; m < toPos; m++)
                            {
                                if (idr.IsFlagSet(cfProcStart, m) || !Flags[m])
                                {
                                    for (int Idx = FirstProcIdx; Idx <= LastProcIdx; Idx++)
                                    {
                                        Idx = KnowledgeBase.ProcOffsets[Idx].NamId;
                                        if (!KnowledgeBase.IsUsedProc(Idx))
                                        {
                                            MProcInfo *pInfo = KnowledgeBase.GetProcInfo(Idx, INFO_DUMP | INFO_ARGS);
                                            //Находим совпадение кода
                                            if (KnowledgeBase.MatchCode(Code + m, pInfo) && StrapCheck(m, pInfo))
                                            {
                                                name = KnowledgeBase.GetModuleName(id);
                                                if (recU->names->IndexOf(name) == -1)
                                                {
                                                    recU->kb = true;
                                                    SetUnitName(recU, name);
                                                }
                                                StrapProc(m, Idx, pInfo, true, pInfo->DumpSz);
                                            }
                                            //as if (pInfo) delete pInfo;
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
    delete[] cnt;
}
*/
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::RedrawCode()
{
    DWORD adr = CurProcAdr;
    CurProcAdr = 0;
    ShowCode(adr, lbCode->ItemIndex, lbCXrefs->ItemIndex, lbCode->TopIndex);
}
//---------------------------------------------------------------------------
//MXXXXXXXX    textF
//M:<,>,=
//XXXXXXXX - adr
//F - flags
int __fastcall TFMain_11011981::AddAsmLine(DWORD Adr, String text, BYTE flags)
{
    String _line = " " + Val2Str8(Adr) + "        " + text + " ";
    if (flags & 1) _line[1] = '>';
    if (flags & 8) _line[10] = '>';
        
    int _len = _line.Length();
    _line[_len] = flags;

    lbCode->Items->Add(_line);
    return lbCode->Canvas->TextWidth(_line);
}
//---------------------------------------------------------------------------
//Argument SelectedIdx can be address (for selection) and index of list
void __fastcall TFMain_11011981::ShowCode(ULONGLONG fromAdr, int SelectedIdx, int XrefIdx, int topIdx)
{
    BYTE        op, flags;
    int         row = 0, wid, maxwid = 0, _pos, _idx, _ap;
    TCanvas*    canvas = lbCode->Canvas;
    int			num, instrLen, instrLen1, instrLen2, _procSize;
    DWORD       Adr, Adr1, Pos, lastMovAdr = 0;
    int         fromPos;
    int         curPos;
    DWORD       curAdr;
    DWORD       lastAdr = 0;
    String      line, line1;
    PInfoRec    recN;
    DISINFO     DisInfo, DisInfo1;
    char        disLine[1024];

    fromPos = Adr2Pos(fromAdr);
    if (fromPos < 0) return;

    bool selectByAdr = (IsValidImageAdr(SelectedIdx) == true);
    //If procedure is the same then move selection and not update Xrefs
    if (fromAdr == CurProcAdr)
    {
        if (selectByAdr)
        {
            for (int i = 1; i < lbCode->Items->Count; i++)
            {
                line = lbCode->Items->Strings[i];
                sscanf(line.c_str() + 1, "%lX", &Adr);
                if (Adr >= SelectedIdx)
                {
                    if (Adr == SelectedIdx)
                    {
                        lbCode->ItemIndex = i;
                        break;
                    }
                    else
                    {
                        lbCode->ItemIndex = i - 1;
                        break;
                    }
                }
            }
        }
        else
            lbCode->ItemIndex = SelectedIdx;

        pcWorkArea->ActivePage = tsCodeView;
        return;
    }
    if (!AnalyzeThread)//Clear all Items (used in highlighting)
    {
        //AnalyzeProc1(fromAdr, 0, 0, 0, false);//!!!
        idr.AnalyzeProc2(fromAdr, false, false);
    }

    CurProcAdr = fromAdr;
    CurProcSize = 0;
	lbCode->Clear();
    lbCode->Items->BeginUpdate();

    recN = GetInfoRec(fromAdr);

    int outRows = MAX_DISASSEMBLE;
    if (idr.IsFlagSet(cfImport, fromPos)) outRows = 2;

    line = " ";
    if (fromAdr == EP)
    {
        line += "EntryPoint";
    }
    else
    {
        String moduleName = "";
        String procName = "";

        PUnitRec recU = GetUnit(fromAdr);
        if (recU)
        {
            moduleName = GetUnitName(recU);
            if (fromAdr == recU->iniadr)
                procName = "Initialization";
            else if (fromAdr == recU->finadr)
                procName = "Finalization";
        }
        if (recN && procName == "") procName = recN->MakeMapName(fromAdr);

        if (moduleName != "")
            line += moduleName + "." + procName;
        else
            line += procName;
    }
    lProcName->Caption = line;
    lbCode->Items->Add(line); row++;

    _procSize = GetProcSize(fromAdr);
    curPos = fromPos; curAdr = fromAdr;

    while (row < outRows)
    {
        //End of procedure
        if (curAdr != fromAdr && _procSize && curAdr - fromAdr >= _procSize) break;
        //Loc?
        flags = ' ';
        if (curAdr != CurProcAdr && idr.IsFlagSet(cfLoc, curPos))
            flags |= 1;
        if (idr.IsFlagSet(cfFrame | cfSkip, curPos))
            flags |= 2;
        if (idr.IsFlagSet(cfLoop, curPos))
            flags |= 4;

        BYTE b1 = Code[curPos];
        BYTE b2 = Code[curPos + 1];
        if (!b1 && !b2 && !lastAdr) break;

        instrLen = GetDisasm().Disassemble(Code + curPos, (__int64)curAdr, &DisInfo, disLine);
        if (!instrLen)
        {
            wid = AddAsmLine(curAdr, "???", 0x22); row++;
            if (wid > maxwid) maxwid = wid;
            curPos++; curAdr++;
            continue;
        }
        op = GetDisasm().GetOp(DisInfo.MnemIdx);

        //Check inside instruction Fixup or ThreadVar
        bool NameInside = false; DWORD NameInsideAdr;
        for (int k = 1; k < instrLen; k++)
        {
            if (idr.HasInfosAt(curPos + k))
            {
                NameInside = true;
                NameInsideAdr= curAdr + k;
                break;
            }
        }

        line = String(disLine);

        if (curAdr >= lastAdr) lastAdr = 0;

        //Proc end
        if (DisInfo.Ret && (!lastAdr || curAdr == lastAdr))
        {
            wid = AddAsmLine(curAdr, line, flags); row++;
            if (wid > maxwid) maxwid = wid;
            break;
        }

        if (op == OP_MOV) lastMovAdr = DisInfo.Offset;

        if (b1 == 0xEB ||				 //short relative abs jmp or cond jmp
        	(b1 >= 0x70 && b1 <= 0x7F) ||
            (b1 == 0xF && b2 >= 0x80 && b2 <= 0x8F))
        {
            Adr = DisInfo.Immediate;
            if (IsValidCodeAdr(Adr))
            {
                if (op == OP_JMP)
                {
                    _ap = Adr2Pos(Adr);
                    recN = GetInfoRec(Adr);
                    if (recN && idr.IsFlagSet(cfProcStart, _ap) && recN->HasName())
                    {
                        line = "jmp         " + recN->GetName();
                    }
                }
                flags |= 8;
                if (Adr >= fromAdr && Adr > lastAdr) lastAdr = Adr;
            }
            wid = AddAsmLine(curAdr, line, flags); row++;
            if (wid > maxwid) maxwid = wid;
            curPos += instrLen; curAdr += instrLen;
            continue;
        }

        if (b1 == 0xE9)    //relative abs jmp or cond jmp
        {
            Adr = DisInfo.Immediate;
            if (IsValidCodeAdr(Adr))
            {
                _ap = Adr2Pos(Adr);
                recN = GetInfoRec(Adr);
                if (recN && idr.IsFlagSet(cfProcStart, _ap) && recN->HasName())
                {
                    line = "jmp         " + recN->GetName();
                }
                flags |= 8;
                if (!recN && Adr >= fromAdr && Adr > lastAdr) lastAdr = Adr;
            }
            wid = AddAsmLine(curAdr, line, flags); row++;
            if (wid > maxwid) maxwid = wid;
            curPos += instrLen; curAdr += instrLen;
            continue;
        }
        
        if (DisInfo.Call)  //call sub_XXXXXXXX
        {
            Adr = DisInfo.Immediate;
            if (IsValidCodeAdr(Adr))
            {
                recN = GetInfoRec(Adr);
                if (recN && recN->HasName())
                {
                    line = "call        " + recN->GetName();
                    //Found @Halt0 - exit
                    if (recN->SameName("@Halt0") && fromAdr == EP && !lastAdr)
                    {
                        wid = AddAsmLine(curAdr, line, flags); row++;
                        if (wid > maxwid) maxwid = wid;
                        break;
                    }
                }
            }
            recN = GetInfoRec(curAdr);
            if (recN && recN->picode) line += ";" + MakeComment(recN->picode);
            wid = AddAsmLine(curAdr, line, flags); row++;
            if (wid > maxwid) maxwid = wid;
            curPos += instrLen; curAdr += instrLen;
            continue;
        }
        //Name inside instruction (Fixip, ThreadVar)
        String namei = "", comment = "", name, pname, type, ptype;
        if (NameInside)
        {
            recN = GetInfoRec(NameInsideAdr);
            if (recN && recN->HasName())
            {
                namei += recN->GetName();
                if (recN->type != "") namei +=  ":" + recN->type;
            }
        }
        //comment
        recN = GetInfoRec(curAdr);
        if (recN && recN->picode) comment = MakeComment(recN->picode);

        DWORD targetAdr = 0;
        if (IsValidImageAdr(DisInfo.Immediate))
        {
        	if (!IsValidImageAdr(DisInfo.Offset)) targetAdr = DisInfo.Immediate;
        }
        else if (IsValidImageAdr(DisInfo.Offset))
        	targetAdr = DisInfo.Offset;

        if (targetAdr)
        {
            name = pname = type = ptype = "";
            _pos = Adr2Pos(targetAdr);
            if (_pos >= 0)
            {
                recN = GetInfoRec(targetAdr);
                if (recN)
                {
                    if (recN->kind == ikResString)
                    {
                        name = recN->GetName() + ":PResStringRec";
                    }
                    else
                    {
                        if (recN->HasName())
                        {
                            name = recN->GetName();
                            if (recN->type != "") type = recN->type;
                        }
                        else if (idr.IsFlagSet(cfProcStart, _pos))
                            name = GetDefaultProcName(targetAdr);
                    }
                }
                Adr = *((DWORD*)(Code + _pos));
                if (IsValidImageAdr(Adr))
                {
                    recN = GetInfoRec(Adr);
                    if (recN)
                    {
                        if (recN->HasName())
                        {
                            pname = recN->GetName();
                            ptype = recN->type;
                        }
                        else if (idr.IsFlagSet(cfProcStart, _pos))
                            pname = GetDefaultProcName(Adr);
                    }
                }
            }
            else
            {
                recN = idr.GetBSSInfosRec(Val2Str8(targetAdr));
                if (recN)
                {
                    name = recN->GetName();
                    type = recN->type;
                }
            }
        }
        if (SameText(comment, name)) name = "";
        if (pname != "")
        {
            if (comment != "") comment += " ";
            comment += "^" + pname;
            if (ptype != "") comment += ":" + ptype;
        }
        else if (name != "")
        {
            if (comment != "") comment += " ";
           	comment += name;
            if (type != "") comment += ":" + type;
        }

        if (comment != "" || namei != "")
        {
            line += ";";
            if (comment != "") line += comment;
            if (namei != "") line += "{" + namei + "}";
        }
        if (line.Length() > MAXLEN) line = line.SubString(1, MAXLEN) + "...";
        wid = AddAsmLine(curAdr, line, flags); row++;
        if (wid > maxwid) maxwid = wid;
        curPos += instrLen; curAdr += instrLen;
    }

    CurProcSize = (curAdr + instrLen) - CurProcAdr;

    pcWorkArea->ActivePage = tsCodeView;
    lbCode->ScrollWidth = maxwid + 2;

    if (selectByAdr)
    {
        for (int i = 1; i < lbCode->Items->Count; i++)
        {
            line = lbCode->Items->Strings[i];
            sscanf(line.c_str() + 1, "%lX", &Adr);
            if (Adr >= SelectedIdx)
            {
                if (Adr == SelectedIdx)
                {
                    lbCode->ItemIndex = i;
                    break;
                }
                else
                {
                    lbCode->ItemIndex = i - 1;
                    break;
                }
            }
        }
    }
    else
        lbCode->ItemIndex = SelectedIdx;

    if (topIdx != -1) lbCode->TopIndex = topIdx;
    lbCode->ItemHeight = lbCode->Canvas->TextHeight("T");
    lbCode->Items->EndUpdate();

    if (-2 == XrefIdx)
        XrefIdx = lbCXrefs->ItemIndex;

    ShowCodeXrefs(CurProcAdr, XrefIdx);
    pcWorkArea->ActivePage = tsCodeView;
}
//---------------------------------------------------------------------------
int __fastcall TFMain_11011981::CodeGetTargetAdr(String Line, DWORD* trgAdr)
{
	char	    *s, *p, c;
    int			n, wid, instrlen;
    DWORD		adr, targetAdr;
    TPoint      cursorPos;
    TCanvas*    canvas = lbCode->Canvas;
    DISINFO     DisInfo;

    *trgAdr = 0;
    s = Line.c_str() + 1;

    //If db - no address
    if (strstr(s, " db ")) return 0;
    //If dd - address
    p = strstr(s, " dd ");
    if (p) sscanf(p + 4, "%lX", &targetAdr);

    if (!IsValidImageAdr(targetAdr))
    {
        sscanf(s, "%lX", &adr);
        instrlen = GetDisasm().Disassemble(Code + Adr2Pos(adr), (__int64)adr, &DisInfo, 0);
        if (!instrlen) return 0;

        if (IsValidImageAdr(DisInfo.Immediate))
        {
            if (!IsValidImageAdr(DisInfo.Offset))
                targetAdr = DisInfo.Immediate;
        }
        else if (IsValidImageAdr(DisInfo.Offset))
            targetAdr = DisInfo.Offset;
    }
    if (!IsValidImageAdr(targetAdr))
    {
        cursorPos = lbCode->ScreenToClient(Mouse->CursorPos);
        for (n = 0, wid = 0; n < strlen(s); n++)
        {
            if (wid >= cursorPos.x)
            {
                while (n >= 0)
                {
                    c = s[n];
                    if (c == ' ' || c == ',' || c == '[' || c == '+')
                    {
                        sscanf(s + n + 1, "%lX", &targetAdr);
                        break;
                    }
                    n--;
                }
                break;
            }
            wid += canvas->TextWidth(s[n]);
        }
    }
    if (IsValidImageAdr(targetAdr)) *trgAdr = targetAdr;
    return DisInfo.OpSize;
}
//---------------------------------------------------------------------------
//May be Plugin!!!
String __fastcall sub_004AFB28(BYTE* AStr)
{
    Integer   _n, _num;
    Byte      _b, _b1, _b2, _m;
    String    _result;

    if (AStr[0] == 0x7B)
    {
        _m = 1;
        _n = 2;
        _b1 = AStr[1];
        _num = _b1 ^ 0xA1;
        _result = "";
        if (_num > 0)
        {
          do
          {
              _b2 = AStr[_n];
              _b1 = (3 * _m + _b1) ^ _b2;
              _b = _b1;
              _b1 = _b2;
              _m = _m + 1;
              _n = _n + 1;
              _num = _num - 1;
              _b2 = AStr[_n];
              _b1 = (3 * _m + _b1) ^ _b2;
              _b = _b | _b1;
              if (_b)
              {
                _result += Char(_b);
              }
              _b1 = _b2;
              _m = _m + 1;
              _n = _n + 1;
              _num = _num - 1;
          }
          while (_num > 0);
        }
    }
    else
    {
        _result = "!";
    }
    return _result;
}
//---------------------------------------------------------------------------
void __fastcall sub_004AF80C(BYTE* AStr1, BYTE* AStr2)
{
    BYTE*   _p;
    BYTE    _b, _n;
    int     _num;

    _n = *(AStr1 + 7);
    _p = AStr1 + 2 + 8;
    _num = AStr2 - _p;
    if (_num > 0)
    {
        do
        {
            _b = *_p;
            _b = ((0xFF - _b + 12) ^ 0xC2) - 3 * _n - 0x62;
            *_p = _b;
            _p++;
            _n++;
            _num--;
        }
        while (_num > 0);
    }
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::lbCodeDblClick(TObject *Sender)
{
    int             pos, bytes, size;
    DWORD		    adr, adr1, targetAdr;
    PInfoRec 		recN;
    PROCHISTORYREC  rec;
    String			text;

    if (lbCode->ItemIndex <= 0) return;

    text = lbCode->Items->Strings[lbCode->ItemIndex];
    size = CodeGetTargetAdr(text, &targetAdr);

    if (IsValidImageAdr(targetAdr))
    {
        pos = Adr2Pos(targetAdr);
        if (pos == -2) return;
        if (pos == -1)
        {
            ShowMessage("BSS");
            return;
        }
        if (idr.IsFlagSet(cfImport, pos))
        {
            ShowMessage("Import");
            return;
        }
        //RTTI
        if (idr.IsFlagSet(cfRTTI, pos))
        {
            FTypeInfo_11011981->ShowRTTI(targetAdr);
            return;
        }
        //if start of procedure, show it
        if (idr.IsFlagSet(cfProcStart, pos))
        {
            rec.adr = CurProcAdr;
            rec.itemIdx = lbCode->ItemIndex;
            rec.xrefIdx = lbCXrefs->ItemIndex;
            rec.topIdx = lbCode->TopIndex;
            ShowCode(Pos2Adr(pos), targetAdr, -1, -1);
            CodeHistoryPush(&rec);
            return;
        }

        recN = GetInfoRec(targetAdr);
        if (recN)
        {
            if (recN->kind == ikVMT && tsClassView->TabVisible)
            {
                ShowClassViewer(targetAdr);
                return;
            }
            if (recN->kind == ikResString)
            {
                FStringInfo_11011981->memStringInfo->Clear();
                FStringInfo_11011981->Caption = "ResString context";
                FStringInfo_11011981->memStringInfo->Lines->Add(recN->rsInfo->value);
                FStringInfo_11011981->ShowModal();
                return;
            }
            if (recN->HasName())
            {
                WORD *uses = KnowledgeBase.GetTypeUses(recN->GetName().c_str());
                int idx = KnowledgeBase.GetTypeIdxByModuleIds(uses, recN->GetName().c_str());
                if (uses) delete[] uses;

                if (idx != -1)
                {
                    idx = KnowledgeBase.TypeOffsets[idx].NamId;
                    MTypeInfo tInfo;
                    if (KnowledgeBase.GetTypeInfo(idx, INFO_FIELDS | INFO_PROPS | INFO_METHODS | INFO_DUMP, &tInfo))
                    {
                        FTypeInfo_11011981->ShowKbInfo(&tInfo);
                        //as delete tInfo;
                        return;
                    }
                }
            }
        }
        //may be ->
        adr = *((DWORD*)(Code + pos));
        if (IsValidImageAdr(adr))
        {
            recN = GetInfoRec(adr);
            if (recN)
            {
                if (recN->kind == ikResString)
                {
                    FStringInfo_11011981->memStringInfo->Clear();
                    FStringInfo_11011981->Caption = "ResString context";
                    FStringInfo_11011981->memStringInfo->Lines->Add(recN->rsInfo->value);
                    FStringInfo_11011981->ShowModal();
                    return;
                }
            }
        }

        //if in current proc
        if (CurProcAdr <= targetAdr && targetAdr < CurProcAdr + CurProcSize)
        {
            rec.adr = CurProcAdr;
            rec.itemIdx = lbCode->ItemIndex;
            rec.xrefIdx = lbCXrefs->ItemIndex;
            rec.topIdx = lbCode->TopIndex;
            ShowCode(CurProcAdr, targetAdr, lbCXrefs->ItemIndex, -1);
            CodeHistoryPush(&rec);
            return;
        }
        //Else show explorer
        FExplorer_11011981->tsCode->TabVisible = true;
        FExplorer_11011981->ShowCode(targetAdr, 1024);
        FExplorer_11011981->tsData->TabVisible = true;
        FExplorer_11011981->ShowData(targetAdr, 1024);
        FExplorer_11011981->tsString->TabVisible = true;
        FExplorer_11011981->ShowString(targetAdr, 1024);
        FExplorer_11011981->tsText->TabVisible = false;
        FExplorer_11011981->pc1->ActivePage = FExplorer_11011981->tsData;
        FExplorer_11011981->WAlign = -4;

        FExplorer_11011981->btnDefCode->Enabled = true;
        if (idr.IsFlagSet(cfCode, pos)) FExplorer_11011981->btnDefCode->Enabled = false;
        FExplorer_11011981->btnUndefCode->Enabled = false;
        if (idr.IsFlagSet(cfCode | cfData, pos)) FExplorer_11011981->btnUndefCode->Enabled = true;

        if (FExplorer_11011981->ShowModal() == mrOk)
        {
            if (FExplorer_11011981->DefineAs == DEFINE_AS_CODE)
            {
                //Delete any information at this address
                recN = GetInfoRec(Pos2Adr(pos));
                if (recN) delete recN;
                //Create new info about proc
                recN = new InfoRec(pos, ikRefine);

                //AnalyzeProcInitial(targetAdr);
                idr.AnalyzeProc1(targetAdr, 0, 0, 0, false);
                idr.AnalyzeProc2(targetAdr, true, true);
                idr.AnalyzeArguments(targetAdr);
                idr.AnalyzeProc2(targetAdr, true, true);

                if (!ContainsUnexplored(GetUnit(targetAdr))) ShowUnits(true);
                ShowUnitItems(GetUnit(targetAdr), lbUnitItems->TopIndex, lbUnitItems->ItemIndex);
                ShowCode(targetAdr, 0, -1, -1);
            }
        }
    }
    //Try picode
    else
    {
        sscanf(text.c_str() + 2, "%lX", &adr);
        recN = GetInfoRec(adr);
        if (recN && recN->picode && IsValidCodeAdr(recN->picode->Ofs.Address))
        {
            pos = Adr2Pos(recN->picode->Ofs.Address);
            if (idr.IsFlagSet(cfProcStart, pos))
            {
                rec.adr = CurProcAdr;
                rec.itemIdx = lbCode->ItemIndex;
                rec.xrefIdx = lbCXrefs->ItemIndex;
                rec.topIdx = lbCode->TopIndex;
                ShowCode(Pos2Adr(pos), targetAdr, -1, -1);
                CodeHistoryPush(&rec);
                return;
            }
        }
    }
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::bEPClick(TObject *Sender)
{
    PROCHISTORYREC  rec;

    rec.adr = CurProcAdr;
    rec.itemIdx = lbCode->ItemIndex;
    rec.xrefIdx = lbCXrefs->ItemIndex;
    rec.topIdx = lbCode->TopIndex;
    ShowCode(EP, 0, -1, -1);
    CodeHistoryPush(&rec);
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::GoToAddress()
{
    int             pos;
    DWORD           gotoAdr;
    String          sAdr;
    PROCHISTORYREC  rec;

    sAdr = InputDialogExec("Enter Address", "Address:", "");
    if (sAdr != "")
    {
        sscanf(sAdr.c_str(), "%lX", &gotoAdr);
        if (IsValidCodeAdr(gotoAdr))
        {
            pos = Adr2Pos(gotoAdr);
            //Если импорт - ничего не отображаем
            if (idr.IsFlagSet(cfImport, pos)) return;
            //Ищем, куда попадает адрес
            while (pos >= 0)
            {
                //Нашли начало процедуры
                if (idr.IsFlagSet(cfProcStart, pos))
                {
                    rec.adr = CurProcAdr;
                    rec.itemIdx = lbCode->ItemIndex;
                    rec.xrefIdx = lbCXrefs->ItemIndex;
                    rec.topIdx = lbCode->TopIndex;
                    ShowCode(Pos2Adr(pos), gotoAdr, -1, -1);
                    CodeHistoryPush(&rec);
                    break;
                }
                //Нашли начало типа
                if (idr.IsFlagSet(cfRTTI, pos))
                {
                    FTypeInfo_11011981->ShowRTTI(Pos2Adr(pos));
                    break;
                }
                pos--;
            }
        }
    }
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::miGoToClick(TObject *Sender)
{
    GoToAddress();
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::miExploreAdrClick(TObject *Sender)
{
    int         size;
	DWORD       viewAdr;
    String      text = "", sAdr;
    PInfoRec    recN;

    if (lbCode->ItemIndex <= 0) return;

    size = CodeGetTargetAdr(lbCode->Items->Strings[lbCode->ItemIndex], &viewAdr);
    if (viewAdr) text = Val2Str8(viewAdr);
    sAdr = InputDialogExec("Enter Address", "Address:", text);
    if (sAdr != "")
    {
        sscanf(sAdr.c_str(), "%lX", &viewAdr);
        if (IsValidImageAdr(viewAdr))
        {
            int pos = Adr2Pos(viewAdr);
            if (pos == -2) return;
            if (pos == -1)
            {
                ShowMessage("BSS");
                return;
            }
            FExplorer_11011981->tsCode->TabVisible = true;
            FExplorer_11011981->ShowCode(viewAdr, 1024);
            FExplorer_11011981->tsData->TabVisible = true;
            FExplorer_11011981->ShowData(viewAdr, 1024);
            FExplorer_11011981->tsString->TabVisible = true;
            FExplorer_11011981->ShowString(viewAdr, 1024);
            FExplorer_11011981->tsText->TabVisible = false;
            FExplorer_11011981->pc1->ActivePage = FExplorer_11011981->tsCode;
            FExplorer_11011981->WAlign = -4;
            
            FExplorer_11011981->btnDefCode->Enabled = true;
            if (idr.IsFlagSet(cfCode, pos)) FExplorer_11011981->btnDefCode->Enabled = false;
            FExplorer_11011981->btnUndefCode->Enabled = false;
            if (idr.IsFlagSet(cfCode | cfData, pos)) FExplorer_11011981->btnUndefCode->Enabled = true;

            if (FExplorer_11011981->ShowModal() == mrOk)
            {
                switch (FExplorer_11011981->DefineAs)
                {
                case DEFINE_AS_CODE:
                    //Delete any information at this address
                    recN = GetInfoRec(viewAdr);
                    if (recN) delete recN;
                    //Create new info about proc
                    recN = new InfoRec(pos, ikRefine);

                    idr.AnalyzeProc1(viewAdr, 0, 0, 0, false);
                    idr.AnalyzeProc2(viewAdr, true, true);
                    idr.AnalyzeArguments(viewAdr);
                    idr.AnalyzeProc2(viewAdr, true, true);

                    if (!ContainsUnexplored(GetUnit(viewAdr))) ShowUnits(true);
                    ShowUnitItems(GetUnit(viewAdr), lbUnitItems->TopIndex, lbUnitItems->ItemIndex);
                    ShowCode(viewAdr, 0, -1, -1);
                    break;
                case DEFINE_AS_STRING:
                    break;
                }
            }
        }
    }
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::NamePosition()
{
	int			pos, _idx, size;
    DWORD 		adr, nameAdr;
    PInfoRec 	recN;
    String 		line, text = "", sNameType, newName, newType;

    if (lbCode->ItemIndex >= 1)
    {
        line = lbCode->Items->Strings[lbCode->ItemIndex];
   	    size = CodeGetTargetAdr(line, &nameAdr);
    }

    if (IsValidImageAdr(nameAdr))
    {
        pos = Adr2Pos(nameAdr);
        recN = GetInfoRec(nameAdr);
        //VMT
        if (recN && recN->kind == ikVMT) return;

        //if (size == 4)
        //{
            adr = *((DWORD*)(Code + pos));
            if (IsValidImageAdr(adr)) nameAdr = adr;
        //}
    }
    else
    {
        nameAdr = CurProcAdr;
    }

    pos = Adr2Pos(nameAdr);
    recN = GetInfoRec(nameAdr);
    if (recN && recN->HasName())
    {
        text = recN->GetName();
        if (recN->type != "") text = recN->GetName() + ":" + recN->type;
    }

    sNameType = InputDialogExec("Enter Name:Type (at " + Val2Str8(nameAdr) + ")", "Name:Type", text);
    if (sNameType != "")
    {
        if (sNameType.Pos(":"))
        {
            newName = ExtractName(sNameType).Trim();
            newType = ExtractType(sNameType).Trim();
        }
        else
        {
            newName = sNameType;
            newType = "";
        }

        if (newName == "") return;

        //If call
        if (pos >= 0 && idr.IsFlagSet(cfProcStart, pos))
        {
            if (!recN) recN = new InfoRec(pos, ikRefine);
            recN->kind = ikProc;
            recN->SetName(newName);
            if (newType != "")
            {
                recN->kind = ikFunc;
                recN->type = newType;
            }
        }
        else
        {
            if (pos >= 0)
            {
                //Address points to Data
                if (!recN) recN = new InfoRec(pos, ikUnknown);
                recN->SetName(newName);
                if (newType != "") recN->type = newType;
            }
            else
            {
                recN = idr.GetBSSInfosRec(Val2Str8(nameAdr));
                if (recN)
                {
                    recN->SetName(newName);
                    recN->type = newType;
                }
                else
                    recN = idr.AddToBSSInfos(nameAdr, newName, newType);
            }
        }

        RedrawCode();
        ShowUnitItems(GetUnit(CurUnitAdr), lbUnitItems->TopIndex, lbUnitItems->ItemIndex);
        ProjectModified = true;
    }
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::miNameClick(TObject *Sender)
{
    NamePosition();
}
//---------------------------------------------------------------------------
TTreeNode* __fastcall TFMain_11011981::GetNodeByName(String AName)
{
    for (int n = 0; n < tvClassesFull->Items->Count; n++)
    {
        TTreeNode *node = tvClassesFull->Items->Item[n];
        String text = node->Text;
        if (AName[1] != ' ')
        {
            if (text[1] != '<' && text[1] == AName[1] && text[2] == AName[2] && text.Pos(AName) == 1) return node;
        }
        else
        {
            if (text[1] != '<' && text.Pos(AName)) return node;
        }
    }
    return 0;
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::ClearTreeNodeMap()
{
    tvClassMap.clear();
}
//---------------------------------------------------------------------------
TTreeNode* __fastcall TFMain_11011981::FindTreeNodeByName(const String& name)
{
    TTreeNodeNameMap::const_iterator it = tvClassMap.find(name);
    if (it != tvClassMap.end()) return it->second;

    return 0;
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::AddTreeNodeWithName(TTreeNode* node, const String& name)
{
    tvClassMap[name] = node;
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::ShowClassViewer(DWORD VmtAdr)
{
    bool        vmtProc;
    WORD        _dx, _bx, _si;
    int         cnt, vmtOfs, _pos;
    DWORD       parentAdr, adr = VmtAdr, vAdr, iAdr;
    ULONGLONG   _rcx;
    DWORD       vmtAdresses[1024];
    String      SelName = GetClsName(VmtAdr), line, name;
    TTreeNode*  selNode = 0;
    TTreeNode*  node = 0;
    PInfoRec    recN;
    PMethodRec  recM;
    DISINFO     disInfo;

    if (SelName == "" || !IsValidImageAdr(VmtAdr)) return;
    
    if (!tsClassView->Enabled) return;
    
    if (ClassTreeDone)
    {
        node = GetNodeByName(SelName + " #" + Val2Str8(adr) + " Sz=");
        if (node)
        {
            node->Selected = true;
            node->Expanded = true;
            tvClassesFull->TopItem = node;
        }
    }

    TList *fieldsList = new TList;
    TStringList *tmpList = new TStringList;
    tmpList->Sorted = false;

    tvClassesShort->Items->Clear(); node = 0;

    for (int n = 0;; n++)
    {
        parentAdr = GetParentAdr(adr);
        vmtAdresses[n] = adr;
        if (!parentAdr)
        {
            while (n >= 0)
            {
                adr = vmtAdresses[n]; n--;
                String className = GetClsName(adr);
                int m, size = GetClassSize(adr); size += 4;

                String text = className + " #" + Val2Str8(adr) + " Sz=" + Val2Str0(size);

                if (!node)  //Root
                    node = tvClassesShort->Items->Add(0, text);
                else
                    node = tvClassesShort->Items->AddChild(node, text);

                if (adr == VmtAdr && SameText(className, SelName)) selNode = node;

                //Interfaces
                int intfsNum = LoadIntfTable(adr, tmpList);
                if (intfsNum)
                {
                    for (m = 0; m < intfsNum; m++)
                    {
                        String item = tmpList->Strings[m];
                        sscanf(item.c_str(), "%lX", &vAdr);
                        if (IsValidCodeAdr(vAdr))
                        {
                            int pos = item.Pos(' ');
                            TTreeNode* intfsNode = tvClassesShort->Items->AddChild(node, "<I> " + item.SubString(pos + 1, item.Length()));
                            cnt = 0;
                            pos = Adr2Pos(vAdr);
                            for (int v = 0;;v += 8)
                            {
                                if (idr.IsFlagSet(cfVTable, pos)) cnt++;
                                if (cnt == 2) break;
                                iAdr = *((DWORD*)(Code + pos));
                                DWORD _adr = iAdr;
                                _pos = Adr2Pos(_adr);
                                vmtProc = false; vmtOfs = 0;
                                _rcx = 0;
                                while (1)
                                {
                                    int instrlen = GetDisasm().Disassemble(Code + _pos, (__int64)_adr, &disInfo, 0);
                                    if ((disInfo.OpType[0] == otMEM || disInfo.OpType[1] == otMEM) &&
                                        disInfo.BaseReg != REG_RSP)//to exclude instruction "xchg reg, [esp]"
                                    {
                                        vmtOfs = disInfo.Offset;
                                    }
                                    if (disInfo.OpType[0] == otREG && disInfo.OpType[1] == otIMM)
                                    {
                                        if (disInfo.OpRegIdx[0] == REG_RCX)
                                            _rcx = disInfo.Immediate;
                                    }
                                    if (disInfo.Call)
                                    {
                                        ShowMessage("Call inside interface entry");
                                        /*
                                        recN = GetInfoRec(disInfo.Immediate);
                                        if (recN)
                                        {
                                            if (recN->SameName("@CallDynaInst") ||
                                                recN->SameName("@CallDynaClass"))
                                            {
                                                GetDynaInfo(adr, _si, &iAdr);
                                                break;
                                            }
                                            else if (recN->SameName("@FindDynaInst") ||
                                                     recN->SameName("@FindDynaClass"))
                                            {
                                                GetDynaInfo(adr, _dx, &iAdr);
                                                break;
                                            }
                                        }
                                        */
                                    }
                                    if (disInfo.Branch && !disInfo.Conditional)
                                    {
                                        if (IsValidImageAdr(disInfo.Immediate))
                                        {
                                            iAdr = disInfo.Immediate;
                                        }
                                        else
                                        {
                                            vmtProc = true;
                                            iAdr = *((DWORD*)(Code + Adr2Pos(VmtAdr - Vmt.SelfPtr + vmtOfs)));
                                            recM = GetMethodInfo(VmtAdr, 'V', vmtOfs);
                                            if (recM) name = recM->name;
                                        }
                                        break;
                                    }
                                    else if (disInfo.Ret)
                                    {
                                        vmtProc = true;
                                        iAdr = *((DWORD*)(Code + Adr2Pos(VmtAdr - Vmt.SelfPtr + vmtOfs)));
                                        recM = GetMethodInfo(VmtAdr, 'V', vmtOfs);
                                        if (recM) name = recM->name;
                                        break;
                                    }
                                    _pos += instrlen; _adr += instrlen;
                                }
                                if (!vmtProc && IsValidImageAdr(iAdr))
                                {
                                    recN = GetInfoRec(iAdr);
                                    if (recN && recN->HasName())
                                        name = recN->GetName();
                                    else
                                        name = "";
                                }
                                line = "I" + Val2Str4(v) + " #" + Val2Str8(iAdr);
                                if (name != "") line += " " + name;
                                tvClassesShort->Items->AddChild(intfsNode, line);
                                pos += 8;
                            }
                        }
                        else
                        {
                            TTreeNode* intfsNode = tvClassesShort->Items->AddChild(node, "<I> " + item);
                        }
                    }
                }
                //Automated
                int autoNum = LoadAutoTable(adr, tmpList);
                if (autoNum)
                {
                    TTreeNode* autoNode = tvClassesShort->Items->AddChild(node, "<A>");
                    for (m = 0; m < autoNum; m++)
                    {
                        tvClassesShort->Items->AddChild(autoNode, tmpList->Strings[m]);
                    }
                }
                //Fields
                int fieldsNum = LoadFieldTable(adr, fieldsList);
                if (fieldsNum)
                {
                    TTreeNode* fieldsNode = tvClassesShort->Items->AddChild(node, "<F>");
                    for (m = 0; m < fieldsNum; m++)
                    {
                        PFIELDINFO fInfo = (PFIELDINFO)fieldsList->Items[m];
                        text = Val2Str5(fInfo->Offset) + " ";
                        if (fInfo->Name != "")
                            text += fInfo->Name;
                        else
                            text += "?";
                        text += ":";
                        if (fInfo->Type != "")
                            text += TrimTypeName(fInfo->Type);
                        else
                            text += "?";

                        tvClassesShort->Items->AddChild(fieldsNode, text);
                    }
                }
                //Events
                int methodsNum = LoadMethodTable(adr, tmpList);
                if (methodsNum)
                {
                    tmpList->Sort();
                    TTreeNode* methodsNode = tvClassesShort->Items->AddChild(node, "<E>");
                    for (m = 0; m < methodsNum; m++)
                    {
                        tvClassesShort->Items->AddChild(methodsNode, tmpList->Strings[m]);
                    }
                }
                int dynamicsNum = LoadDynamicTable(adr, tmpList);
                if (dynamicsNum)
                {
                    tmpList->Sort();
                    TTreeNode* dynamicsNode = tvClassesShort->Items->AddChild(node, "<D>");
                    for (m = 0; m < dynamicsNum; m++)
                    {
                        tvClassesShort->Items->AddChild(dynamicsNode, tmpList->Strings[m]);
                    }
                }
                //Virtual
                int virtualsNum = LoadVirtualTable(adr, tmpList);
                if (virtualsNum)
                {
                    TTreeNode* virtualsNode = tvClassesShort->Items->AddChild(node, "<V>");
                    for (m = 0; m < virtualsNum; m++)
                    {
                        tvClassesShort->Items->AddChild(virtualsNode, tmpList->Strings[m]);
                    }
                }
            }
            if (selNode)
            {
                selNode->Selected = true;
                selNode->Expand(true);
                tvClassesShort->TopItem = selNode;
            }
            break;
        }
        adr = parentAdr;
    }

    delete fieldsList;
    delete tmpList;

    pcWorkArea->ActivePage = tsClassView;
    if (!rgViewerMode->ItemIndex)
    {
        tvClassesFull->BringToFront();
    }
    else
    {
        tvClassesShort->BringToFront();
    }
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::miViewProtoClick(TObject *Sender)
{
    int         Idx;
    DWORD		Adr;
    PInfoRec 	recN;
    MProcInfo   pInfo;
    String      item;
    DISINFO     DisInfo;

    if (lbCode->ItemIndex <= 0) return;

    item = lbCode->Items->Strings[lbCode->ItemIndex];
    sscanf(item.c_str() + 1, "%lX", &Adr);
    int instrlen = GetDisasm().Disassemble(Code + Adr2Pos(Adr), (__int64)Adr, &DisInfo, 0);
    if (!instrlen) return;
    
    String proto = "";
    if (DisInfo.Call)
    {
    	//Адрес задан явно
        if (IsValidCodeAdr(DisInfo.Immediate))
        {
            recN = GetInfoRec(DisInfo.Immediate);
            if (recN) proto = recN->MakePrototype(DisInfo.Immediate, true, false, false, true, true);
        }
        //Адрес не задан, пробуем пи-код
        else
        {
        	recN = GetInfoRec(Adr);
            if (recN && recN->picode && IsValidCodeAdr(recN->picode->Ofs.Address))
            {
                if (KnowledgeBase.GetProcInfo(recN->picode->Name.c_str(), INFO_ARGS, &pInfo, &Idx))
                    proto = KnowledgeBase.GetProcPrototype(&pInfo);
            }
        }
    }
    if (proto != "")
    {
        FStringInfo_11011981->memStringInfo->Clear();
        FStringInfo_11011981->Caption = "Prototype";
        FStringInfo_11011981->memStringInfo->Lines->Add(proto);
        FStringInfo_11011981->ShowModal();
    }
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::ShowCXrefsClick(TObject *Sender)
{
    if (lbCXrefs->Visible)
    {
        ShowCXrefs->BevelOuter = bvRaised;
        lbCXrefs->Visible = false;
    }
    else
    {
        ShowCXrefs->BevelOuter = bvLowered;
        lbCXrefs->Visible = true;
    }
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::bCodePrevClick(TObject *Sender)
{
	//first add to array current subroutine info (for ->)
    if (CodeHistoryPtr == CodeHistorySize - 1)
    {
        CodeHistorySize += HISTORY_CHUNK_LENGTH;
        CodeHistory.Length = CodeHistorySize;
    }

    PROCHISTORYREC rec;
    rec.adr = CurProcAdr;
    rec.itemIdx = lbCode->ItemIndex;
    rec.xrefIdx = lbCXrefs->ItemIndex;
    rec.topIdx = lbCode->TopIndex;
    memmove(&CodeHistory[CodeHistoryPtr + 1], &rec, sizeof(PROCHISTORYREC));
    //next pop from array
    PPROCHISTORYREC prec = CodeHistoryPop();
    if (prec) ShowCode(prec->adr, prec->itemIdx, prec->xrefIdx, prec->topIdx);
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::bCodeNextClick(TObject *Sender)
{
    PROCHISTORYREC rec;
    rec.adr = CurProcAdr;
    rec.itemIdx = lbCode->ItemIndex;
    rec.xrefIdx = lbCXrefs->ItemIndex;
    rec.topIdx = lbCode->TopIndex;

	CodeHistoryPtr++;
    memmove(&CodeHistory[CodeHistoryPtr], &rec, sizeof(PROCHISTORYREC));

	PPROCHISTORYREC prec = &CodeHistory[CodeHistoryPtr + 1];
    ShowCode(prec->adr, prec->itemIdx, prec->xrefIdx, prec->topIdx);
    
    bCodePrev->Enabled = (CodeHistoryPtr >= 0);
    bCodeNext->Enabled = (CodeHistoryPtr < CodeHistoryMax);
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::CodeHistoryPush(PPROCHISTORYREC rec)
{
    if (CodeHistoryPtr == CodeHistorySize - 1)
    {
        CodeHistorySize += HISTORY_CHUNK_LENGTH;
        CodeHistory.Length = CodeHistorySize;
    }

    CodeHistoryPtr++;
    memmove(&CodeHistory[CodeHistoryPtr], rec, sizeof(PROCHISTORYREC));

    CodeHistoryMax = CodeHistoryPtr;
    bCodePrev->Enabled = (CodeHistoryPtr >= 0);
    bCodeNext->Enabled = (CodeHistoryPtr < CodeHistoryMax);
}
//---------------------------------------------------------------------------
PPROCHISTORYREC __fastcall TFMain_11011981::CodeHistoryPop()
{
    PPROCHISTORYREC prec = 0;
    if (CodeHistoryPtr >= 0)
    {
        prec = &CodeHistory[CodeHistoryPtr];
        CodeHistoryPtr--;
    }
    bCodePrev->Enabled = (CodeHistoryPtr >= 0);
    bCodeNext->Enabled = (CodeHistoryPtr < CodeHistoryMax);
    return prec;
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::tvClassesDblClick(TObject *Sender)
{
    int             k, m, n;
    TTreeView*      tv;
    PROCHISTORYREC  rec;

    if (ActiveControl == tvClassesFull || ActiveControl == tvClassesShort)
        tv = (TTreeView*)ActiveControl;

    TTreeNode   *node = tv->Selected;
    if (node)
    {
        DWORD adr;
        String line = node->Text;
        int pos = line.Pos("#");
        //Указан адрес
        if (pos && !line.Pos("Sz="))
        {
            sscanf(line.c_str() + pos, "%lX", &adr);
            if (IsValidCodeAdr(adr))
            {
                rec.adr = CurProcAdr;
                rec.itemIdx = lbCode->ItemIndex;
                rec.xrefIdx = lbCXrefs->ItemIndex;
                rec.topIdx = lbCode->TopIndex;
                ShowCode(adr, 0, -1, -1);
                CodeHistoryPush(&rec);
            }
            return;
        }
        //Указан тип поля
        if (line.Pos(":"))
        {
            String typeName = ExtractType(line);
            //Если тип задан в виде Unit.TypeName
            if (typeName.Pos(".")) typeName = ExtractProcName(typeName);

            adr = GetClassAdr(typeName);
            if (IsValidImageAdr(adr))
            {
                ShowClassViewer(adr);
            }
            else
            {
                WORD* uses = KnowledgeBase.GetTypeUses(typeName.c_str());
                int Idx = KnowledgeBase.GetTypeIdxByModuleIds(uses, typeName.c_str());
                if (Idx != -1)
                {
                    Idx = KnowledgeBase.TypeOffsets[Idx].NamId;
                    MTypeInfo tInfo;
                    if (KnowledgeBase.GetTypeInfo(Idx, INFO_FIELDS | INFO_PROPS | INFO_METHODS, &tInfo))
                    {
                        FTypeInfo_11011981->ShowKbInfo(&tInfo);
                        //as delete tInfo;
                    }
                }
                if (uses) delete[] uses;
            }
        }
    }
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::tvClassesShortKeyDown(TObject *Sender,
      WORD &Key, TShiftState Shift)
{
    if (Key == VK_RETURN) tvClassesDblClick(Sender);
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::pmVMTsPopup(TObject *Sender)
{
	bool	b;
	if (ActiveControl == tvClassesFull)
    {
    	b = (tvClassesFull->Items->Count != 0);
    	miSearchVMT->Visible = b;
        miCollapseAll->Visible = b;
        miEditClass->Visible = false;
        return;
    }
    if (ActiveControl == tvClassesShort)
    {
    	b = (tvClassesShort->Items->Count != 0);
    	miSearchVMT->Visible = b;
        miCollapseAll->Visible = b;
        miEditClass->Visible = !AnalyzeThread && b && tvClassesShort->Selected;
        return;
    }
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::miViewClassClick(TObject *Sender)
{
    String sName = InputDialogExec("Enter Name of Type", "Name:", "");
    if (sName != "") ShowClassViewer(GetClassAdr(sName));
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::miSearchVMTClick(TObject *Sender)
{
    WhereSearch = SEARCH_CLASSVIEWER;

    FindDlg_11011981->cbText->Clear();
    for (int n = 0; n < VMTsSearchList->Count; n++)
        FindDlg_11011981->cbText->AddItem(VMTsSearchList->Strings[n], 0);

    if (FindDlg_11011981->ShowModal() == mrOk && FindDlg_11011981->cbText->Text != "")
    {
        if (ActiveControl == tvClassesFull)
        {
            if (tvClassesFull->Selected)
                TreeSearchFrom = tvClassesFull->Selected;
            else
                TreeSearchFrom = tvClassesFull->Items->Item[0];
        }
        else if (ActiveControl == tvClassesShort)
        {
            if (tvClassesShort->Selected)
                BranchSearchFrom = tvClassesShort->Selected;
            else
                BranchSearchFrom = tvClassesShort->Items->Item[0];
        }

        VMTsSearchText = FindDlg_11011981->cbText->Text;
        if (VMTsSearchList->IndexOf(VMTsSearchText) == -1) VMTsSearchList->Add(VMTsSearchText);
        FindText(VMTsSearchText);
    }
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::miCollapseAllClick(TObject *Sender)
{
    TTreeView* tv;
    if (ActiveControl == tvClassesFull || ActiveControl == tvClassesShort)
    {
        tv = (TTreeView*)ActiveControl;
        tv->Items->BeginUpdate();
        TTreeNode* rootNode = tv->Items->Item[0];
        const int cnt = rootNode->Count;
        for (int n = 0; n < cnt; n++)
        {
            TTreeNode* node = rootNode->Item[n];
            if (node->HasChildren && node->Expanded) node->Collapse(true);
        }
        tv->Items->EndUpdate();
    }
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::miEditClassClick(TObject *Sender)
{
	if (ActiveControl == tvClassesShort)
    {
    	TTreeNode* node = tvClassesShort->Selected;
        if (node)
        {
            int FieldOfs = -1;
            if (!node->Text.Pos("#"))
                sscanf(node->Text.c_str(), "%lX", &FieldOfs);
        	while (node)
            {
                int pos = node->Text.Pos("#");
                //Указан адрес
                if (pos && node->Text.Pos("Sz="))
                {
                	DWORD vmtAdr;
                    sscanf(node->Text.c_str() + pos, "%lX", &vmtAdr);
                    if (IsValidImageAdr(vmtAdr))
                    {
                    	FEditFieldsDlg_11011981->VmtAdr = vmtAdr;
                        FEditFieldsDlg_11011981->FieldOffset = FieldOfs;
                        if (FEditFieldsDlg_11011981->Visible) FEditFieldsDlg_11011981->Close();
                        FEditFieldsDlg_11011981->FormStyle = fsStayOnTop;
                    	FEditFieldsDlg_11011981->Show();
                        //TODO: check for FEditFieldsDlg_11011981->Modified();  when?
                        return;
                    }
                }
                node = node->GetPrev();
            }
        }
    }
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::miCopyCodeClick(TObject *Sender)
{
    Copy2Clipboard(lbCode->Items, 1, true);
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::lbFormsDblClick(TObject *Sender)
{
	int		n, m;

    //TDfm *dfm = (TDfm*)ResInfo->FormList->Items[lbForms->ItemIndex];
    TDfm *dfm = idr.ResInfo()->GetDfm(lbForms->ItemIndex);

    switch (rgViewFormAs->ItemIndex)
    {
    //As Text
    case 0:
        FExplorer_11011981->tsCode->TabVisible = false;
        FExplorer_11011981->tsData->TabVisible = false;
        FExplorer_11011981->tsString->TabVisible = false;
        FExplorer_11011981->tsText->TabVisible = true;
        FExplorer_11011981->pc1->ActivePage = FExplorer_11011981->tsText;
        idr.ResInfo()->GetFormAsText(dfm, FExplorer_11011981->lbText->Items);
        FExplorer_11011981->ShowModal();
        break;
    //As Form
    case 1:
        if (dfm->Open != 2)
        {
            //Если есть открытые формы, закрываем их
            idr.ResInfo()->CloseAllForms();

            ShowDfm(dfm);
        }
        break;
    }
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::ShowDfm(TDfm* dfm)
{
    if (!dfm)
        return;
        
    //if inherited find parent form
    if ((dfm->Flags & FF_INHERITED) && !dfm->ParentDfm)
        dfm->ParentDfm = idr.ResInfo()->GetParentDfm(dfm);

    dfm->Loader = new IdrDfmLoader(0);
    dfm->Form = dfm->Loader->LoadForm(dfm->MemStream, dfm);
    delete dfm->Loader;
    dfm->Loader = 0;

    if (dfm->Form)
    {
        PUnitRec recU = GetUnit(GetClassAdr(dfm->ClassName));
        if (recU)
        {
            String StringBuf1;
            StringBuf1.sprintf("[#%03d] %s", recU->iniOrder, dfm->Form->Caption.c_str());
            dfm->Form->Caption = StringBuf1;
        }
        dfm->Open = 2;
        dfm->Form->Show();

        //if (!AnalyzeThread)
        //    sb->Panels->Items[0]->Text = "Press F11 to open form controls tree";
    }
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::lbFormsKeyDown(TObject *Sender, WORD &Key,
      TShiftState Shift)
{
    if (lbForms->ItemIndex >= 0 && Key == VK_RETURN) lbFormsDblClick(Sender);
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::lbCodeKeyDown(TObject *Sender,
      WORD &Key, TShiftState Shift)
{
    switch (Key)
    {
    case VK_RETURN:
        lbCodeDblClick(Sender);
        break;
    case VK_ESCAPE:
    	bCodePrevClick(Sender);
        break;
    }
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::CleanProject()
{
    idr.CleanProject();

    int n;

    //TODO: think about CleanupList<> usage
    for (n = 0; n < ExpFuncList->Count; n++)
    {
        PExportNameRec recE = (PExportNameRec)ExpFuncList->Items[n];
        delete recE;
    }
    ExpFuncList->Clear();

    for (n = 0; n < ImpFuncList->Count; n++)
    {
        PImportNameRec recI = (PImportNameRec)ImpFuncList->Items[n];
        delete recI;
    }
    ImpFuncList->Clear();
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::CloseProject()
{
    CleanProject();

    idr.ResInfo()->CloseAllForms();
    idr.ResInfo()->Clean();

    OwnTypeList->Clear();

    UnitsSearchList->Clear();
    RTTIsSearchList->Clear();
    UnitItemsSearchList->Clear();
    VMTsSearchList->Clear();
    FormsSearchList->Clear();
    StringsSearchList->Clear();
    NamesSearchList->Clear();

    CodeHistoryPtr = -1;
    CodeHistoryMax = CodeHistoryPtr;
    CodeHistory.Length = 0;

    KnowledgeBase.Close();
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::tvClassesFullClick(TObject *Sender)
{
    TreeSearchFrom = tvClassesFull->Selected;
    WhereSearch = SEARCH_CLASSVIEWER;
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::tvClassesShortClick(TObject *Sender)
{
    BranchSearchFrom = tvClassesShort->Selected;
    WhereSearch = SEARCH_CLASSVIEWER;
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::FindText(String Text)
{
    int         n, pos, idx = -1;
    String      line, findText, msg;
    TTreeNode*  node;
    TTreeView*  tv;

    if (Text == "") return;
    
    msg = "Search string \"" + Text + "\" not found";

    switch (WhereSearch)
    {
    case SEARCH_UNITS:
        for (n = UnitsSearchFrom; n < lbUnits->Items->Count; n++)
        {
            if (AnsiContainsText(lbUnits->Items->Strings[n], Text))
            {
                idx = n;
                break;
            }
        }
        if (idx == -1)
        {
            for (n = 0; n < UnitsSearchFrom; n++)
            {
                if (AnsiContainsText(lbUnits->Items->Strings[n], Text))
                {
                    idx = n;
                    break;
                }
            }
        }
        if (idx != -1)
        {
        	UnitsSearchFrom = (idx < lbUnits->Items->Count - 1) ? idx + 1 : 0;
            lbUnits->ItemIndex = idx;
            lbUnits->SetFocus();
        }
        else
        {
            ShowMessage(msg);
        }
        break;
    case SEARCH_UNITITEMS:
        for (n = UnitItemsSearchFrom; n < lbUnitItems->Items->Count; n++)
        {
            if (AnsiContainsText(lbUnitItems->Items->Strings[n], Text))
            {
                idx = n;
                break;
            }
        }
        if (idx == -1)
        {
            for (n = 0; n < UnitItemsSearchFrom; n++)
            {
                if (AnsiContainsText(lbUnitItems->Items->Strings[n], Text))
                {
                    idx = n;
                    break;
                }
            }
		}
        if (idx != -1)
        {
        	UnitItemsSearchFrom = (idx < lbUnitItems->Items->Count) ? idx + 1 : 0;
            lbUnitItems->ItemIndex = idx;
            lbUnitItems->SetFocus();
        }
        else
        {
            ShowMessage(msg);
        }
        break;
    case SEARCH_RTTIS:
        for (n = RTTIsSearchFrom; n < lbRTTIs->Items->Count; n++)
        {
            if (AnsiContainsText(lbRTTIs->Items->Strings[n], Text))
            {
            	idx = n;
                break;
            }
        }
        if (idx == -1)
        {
            for (n = 0; n < RTTIsSearchFrom; n++)
            {
                if (AnsiContainsText(lbRTTIs->Items->Strings[n], Text))
                {
                	idx = n;
                    break;
                }
            }
        }
        if (idx != -1)
        {
        	RTTIsSearchFrom = (idx < lbRTTIs->Items->Count - 1) ? idx + 1 : 0;
            lbRTTIs->ItemIndex = idx;
        	lbRTTIs->SetFocus();
        }
        else
        {
            ShowMessage(msg);
        }
        break;
    case SEARCH_FORMS:
        for (n = FormsSearchFrom; n < lbForms->Items->Count; n++)
        {
            if (AnsiContainsText(lbForms->Items->Strings[n], Text))
            {
            	idx = n;
                break;
            }
        }
        if (idx == -1)
        {
            for (n = 0; n < FormsSearchFrom; n++)
            {
                if (AnsiContainsText(lbForms->Items->Strings[n], Text))
                {
                	idx = n;
                    break;
                }
            }
        }
        if (idx != -1)
        {
        	FormsSearchFrom = (idx < lbForms->Items->Count - 1) ? idx + 1 : 0;
            lbForms->ItemIndex = idx;
        	lbForms->SetFocus();
        }
        else
        {
            ShowMessage(msg);
        }
        break;
    case SEARCH_CLASSVIEWER:
        if (!rgViewerMode->ItemIndex)
        {
        	node = TreeSearchFrom;
            while (node)
            {
            	line = node->Text;
                //Skip <>
                if (line[1] != '<' && AnsiContainsText(line, Text))
                {
                    idx = 0;
                    break;
                }
                node = node->GetNext();
            }
            if (idx == -1 && tvClassesFull->Items->Count)
            {
            	node = tvClassesFull->Items->Item[0];
            	while (node != TreeSearchFrom)
                {
                    line = node->Text;
                    //Skip <>
                    if (line[1] != '<' && AnsiContainsText(line, Text))
                    {
                        idx = 0;
                        break;
                    }
                    node = node->GetNext();
                }
            }
            if (idx != -1)
            {
                TreeSearchFrom = (node->GetNext()) ? node->GetNext() : tvClassesFull->Items->Item[0];
                node->Selected = true;
                node->Expanded = true;
                tvClassesFull->Show();
            }
            else
            {
                ShowMessage(msg);
            }
        }
        else
        {
        	node = BranchSearchFrom;
            while (node)
            {
            	line = node->Text;
                //Skip <>
                if (line[1] != '<' && AnsiContainsText(line, Text))
                {
                    idx = 0;
                    break;
                }
                node = node->GetNext();
            }
            if (idx == -1 && tvClassesShort->Items->Count)
            {
            	node = tvClassesShort->Items->Item[0];
            	while (node != BranchSearchFrom)
                {
                    line = node->Text;
                    //Skip <>
                    if (line[1] != '<' && AnsiContainsText(line, Text))
                    {
                        idx = 0;
                        break;
                    }
                    node = node->GetNext();
                }
            }
            if (idx != -1)
            {
                BranchSearchFrom = (node->GetNext()) ? node->GetNext() : tvClassesShort->Items->Item[0];
                node->Selected = true;
                node->Expanded = true;
                tvClassesShort->Show();
            }
            else
            {
                ShowMessage(msg);
            }
        }
        break;
    case SEARCH_STRINGS:
        for (n = StringsSearchFrom; n < lbStrings->Items->Count; n++)
        {
        	line = lbStrings->Items->Strings[n];
        	pos = line.Pos("'");
        	line = line.SubString(pos + 1, line.Length() - pos);
            if (AnsiContainsText(line, Text))
            {
                idx = n;
                break;
            }
        }
        if (idx == -1)
        {
            for (n = 0; n < StringsSearchFrom; n++)
            {
                line = lbStrings->Items->Strings[n];
                pos = line.Pos("'");
                line = line.SubString(pos + 1, line.Length() - pos);
                if (AnsiContainsText(line, Text))
                {
                    idx = n;
                    break;
                }
            }
        }
        if (idx != -1)
        {
        	StringsSearchFrom = (idx < lbStrings->Items->Count - 1) ? idx + 1 : 0;
            lbStrings->ItemIndex = idx;
            lbStrings->SetFocus();
        }
        else
        {
            ShowMessage(msg);
        }
    	break;
    case SEARCH_NAMES:
        for (n = NamesSearchFrom; n < lbNames->Items->Count; n++)
        {
        	line = lbNames->Items->Strings[n];
            if (AnsiContainsText(line, Text))
            {
                idx = n;
                break;
            }
        }
        if (idx == -1)
        {
            for (n = 0; n < NamesSearchFrom; n++)
            {
                line = lbNames->Items->Strings[n];
                if (AnsiContainsText(line, Text))
                {
                    idx = n;
                    break;
                }
            }
        }
        if (idx != -1)
        {
        	NamesSearchFrom = (idx < lbNames->Items->Count - 1) ? idx + 1 : 0;
            lbNames->ItemIndex = idx;
            lbNames->SetFocus();
        }
        else
        {
            ShowMessage(msg);
        }
    	break;
    }
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::lbFormsMouseMove(TObject *Sender,
      TShiftState Shift, int X, int Y)
{
    if (lbForms->CanFocus()) ActiveControl = lbForms;
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::lbCodeMouseMove(TObject *Sender,
      TShiftState Shift, int X, int Y)
{
    if (lbCode->CanFocus()) ActiveControl = lbCode;
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::tvClassesFullMouseMove(
      TObject *Sender, TShiftState Shift, int X, int Y)
{
    if (tvClassesFull->CanFocus()) ActiveControl = tvClassesFull;
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::tvClassesShortMouseMove(TObject *Sender,
      TShiftState Shift, int X, int Y)
{
    if (tvClassesShort->CanFocus()) ActiveControl = tvClassesShort;
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::rgViewerModeClick(TObject *Sender)
{
    if (!rgViewerMode->ItemIndex)
        tvClassesFull->BringToFront();
    else
        tvClassesShort->BringToFront();
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::miClassTreeBuilderClick(TObject *Sender)
{
    miLoadFile->Enabled = false;
    miOpenProject->Enabled = false;
    miMRF->Enabled = false;
    miSaveProject->Enabled = false;
    miSaveDelphiProject->Enabled = false;
    miMapGenerator->Enabled = false;
    miCommentsGenerator->Enabled = false;
    miIDCGenerator->Enabled = false;
    miLister->Enabled = false;
    miClassTreeBuilder->Enabled = false;
    miKBTypeInfo->Enabled = false;
    miCtdPassword->Enabled = false;
    miHex2Double->Enabled = false;

    FProgressBar->Show();
    AnalyzeThread = new TAnalyzeThread(this->Handle, FProgressBar->Handle, false);
    AnalyzeThread->Resume();
}
//---------------------------------------------------------------------------
//INI FILE
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::IniFileRead()
{
    int         n, m, pos, version; String str, filename, ident;
    TMenuItem   *item;
    TIniFile    *iniFile;
    TFont       *_font;
    TMonitor    *_monitor;

    iniFile = new TIniFile(ChangeFileExt(Application->ExeName, ".ini"));

    _font = new TFont;
    _font->Name = iniFile->ReadString("Settings", "FontName", "Fixedsys");
    _font->Charset = iniFile->ReadInteger("Settings", "FontCharset", 1);
    _font->Size = iniFile->ReadInteger("Settings", "FontSize", 9);
    _font->Color = iniFile->ReadInteger("Settings", "FontColor", 0);
    if (iniFile->ReadBool("Settings", "FontBold", False))
        _font->Style = _font->Style << fsBold;
    if (iniFile->ReadBool("Settings", "FontItalic", False))
        _font->Style = _font->Style << fsItalic;
    SetupAllFonts(_font);
    delete _font;

    idr.WrkDir = WrkDir = iniFile->ReadString("MainForm", "WorkingDir", AppDir);

    for (n = 0; n < Screen->MonitorCount; n++)
    {
        _monitor = Screen->Monitors[n];
        if (_monitor->Primary)
        {
            Left = iniFile->ReadInteger("MainForm", "Left", _monitor->WorkareaRect.Left);
            Top = iniFile->ReadInteger("MainForm", "Top", _monitor->WorkareaRect.Top);
            Width = iniFile->ReadInteger("MainForm", "Width", _monitor->WorkareaRect.Width());
            Height = iniFile->ReadInteger("MainForm", "Height", _monitor->WorkareaRect.Height());
            break;
        }
    }
    pcInfo->Width = iniFile->ReadInteger("MainForm", "LeftWidth", Width / 5);
    pcInfo->ActivePage = tsUnits;
    lbUnitItems->Height = iniFile->ReadInteger("MainForm", "BottomHeight", Height / 8);
    //Most Recent Files

    for (n = 0, m = 0; n < 8; n++)
    {
        ident = "File" + String(n + 1);
        str = iniFile->ReadString("Recent Executable Files", ident, "");
        pos = str.LastDelimiter(",");
        if (pos)
        {
            filename = str.SubString(2, pos - 3);   //Modified by ZGL
            version = str.SubString(pos + 1, str.Length() - pos).ToInt();
        }
        else
        {
            filename = str;
            version = -1;
        }
        if (FileExists(filename))
        {
            item = miMRF->Items[m]; m++;
            item->Caption = filename;
            item->Tag = version;
            item->Visible = (filename != "");
            item->Enabled = true;
        }
        else
        {
            iniFile->DeleteKey("Recent Executable Files", ident);
        }
    }
    for (n = 9, m = 9; n < 17; n++)
    {
        ident = "File" + String(n - 8);
        filename = iniFile->ReadString("Recent Project Files", ident, "");
        if (FileExists(filename))
        {
            item = miMRF->Items[m]; m++;
            item->Caption = filename;
            item->Tag = 0;
            item->Visible = (item->Caption != "");
            item->Enabled = true;
        }
        else
        {
            iniFile->DeleteKey("Recent Project Files", ident);
        }
    }
    delete iniFile;
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::IniFileWrite()
{
    TIniFile *iniFile = new TIniFile(ChangeFileExt(Application->ExeName, ".ini"));
    iniFile->WriteString("Settings", "FontName", lbCode->Font->Name);
    iniFile->WriteInteger("Settings", "FontCharset", lbCode->Font->Charset);
    iniFile->WriteInteger("Settings", "FontSize", lbCode->Font->Size);
    iniFile->WriteInteger("Settings", "FontColor", lbCode->Font->Color);
    iniFile->WriteBool("Settings", "FontBold", lbCode->Font->Style.Contains(fsBold));
    iniFile->WriteBool("Settings", "FontItalic", lbCode->Font->Style.Contains(fsItalic));

    iniFile->WriteString("MainForm", "WorkingDir", WrkDir);
    iniFile->WriteInteger("MainForm", "Left", Left);
    iniFile->WriteInteger("MainForm", "Top", Top);
    iniFile->WriteInteger("MainForm", "Width", Width);
    iniFile->WriteInteger("MainForm", "Height", Height);
    iniFile->WriteInteger("MainForm", "LeftWidth", pcInfo->Width);
    iniFile->WriteInteger("MainForm", "BottomHeight", lbUnitItems->Height);

    //Delete all
    int n; String ident;
    for (n = 0; n < 8; n++) iniFile->DeleteKey("Recent Executable Files", "File" + String(n + 1));
    for (n = 9; n < 17; n++) iniFile->DeleteKey("Recent Executable Files", "File" + String(n - 8));

    //Fill
    for (n = 0; n < 8; n++)
    {
        TMenuItem *item = miMRF->Items[n];
        if (item->Visible && item->Enabled) iniFile->WriteString("Recent Executable Files", "File" + String(n + 1), "\"" + item->Caption + "\"," + String(item->Tag));
    }
    for (n = 9; n < 17; n++)
    {
        TMenuItem *item = miMRF->Items[n];
        if (item->Visible && item->Enabled) iniFile->WriteString("Recent Project Files", "File" + String(n - 8), "\"" + item->Caption + "\"");
    }

    delete iniFile;
}
//---------------------------------------------------------------------------
//LOAD EXE AND IDP
//---------------------------------------------------------------------------
bool __fastcall TFMain_11011981::IsExe(String FileName)
{
    IMAGE_DOS_HEADER    DosHeader;
    IMAGE_NT_HEADERS    NTHeaders;

    FILE* f = fopen(FileName.c_str(), "rb");
    if (!f) return false;

    fseek(f, 0, SEEK_SET);
    //IDD_ERR_NOT_EXECUTABLE
    int readed = fread(&DosHeader, 1, sizeof(DosHeader), f);

    if (readed != sizeof(IMAGE_DOS_HEADER) ||
        DosHeader.e_magic != IMAGE_DOS_SIGNATURE)
    {
        fclose(f);
        return false;
    }

    fseek(f, DosHeader.e_lfanew, SEEK_SET);
    //IDD_ERR_NOT_PE_EXECUTABLE
    readed = fread(&NTHeaders, 1, sizeof(NTHeaders), f);
    fclose(f);
    if (readed != sizeof(IMAGE_NT_HEADERS) ||
        NTHeaders.Signature != IMAGE_NT_SIGNATURE)
    {
        return false;
    }
    return true;
}
//---------------------------------------------------------------------------
bool __fastcall TFMain_11011981::IsIdp(String FileName)
{
    char    buf[IDPMAGICLEN + 1] = {0};

    FILE* f = fopen(FileName.c_str(), "rb");
    if (!f) return false;

    fseek(f, 0, SEEK_SET);
    fread(buf, 1, IDPMAGICLEN, f); buf[IDPMAGICLEN] = 0;
    fclose(f);
    
    if (!strcmp(buf, IDPMAGIC)) return true;
    return false;
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::miAutodetectVersionClick(TObject *Sender)
{
    LoadDelphiFile(0);
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::miDelphiXE2Click(TObject *Sender)
{
    LoadDelphiFile(2012);
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::miDelphiXE3Click(TObject *Sender)
{
    LoadDelphiFile(2013);
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::miDelphiXE4Click(TObject *Sender)
{
    LoadDelphiFile(2014);
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::LoadFile(String FileName, int version)
{
    if (ProjectModified)
    {
        int res = Application->MessageBox("Save active Project?", "Confirmation", MB_YESNOCANCEL | MB_ICONQUESTION);
        if (res == IDCANCEL) return;
        if (res == IDYES)
        {
            if (IDPFile == "") IDPFile = ChangeFileExt(SourceFile, ".idp");

            SaveDlg->InitialDir = WrkDir;
            SaveDlg->Filter = "IDP|*.idp";
            SaveDlg->FileName = IDPFile;

            if (SaveDlg->Execute()) SaveProject(SaveDlg->FileName);
        }
    }

    if (IsExe(FileName))
    {
        CloseProject();
        Init();
        LoadDelphiFile1(FileName, version, true, true);
    }
    else if (IsIdp(FileName))
    {
        CloseProject();
        Init();
        OpenProject(FileName);
    }
    else
    {
        //ShowMessage("File " + FileName + " is not executable or IDR project file");
        LogMessage("File " + FileName + " is not executable or IDR project file", MB_ICONWARNING);
    }
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::LoadDelphiFile(int version)
{
	DoOpenDelphiFile(version, "", true, true);
}
//---------------------------------------------------------------------------
//version: 0 for autodetect, else - exact version
//
void __fastcall TFMain_11011981::DoOpenDelphiFile(int version, String FileName, bool loadExp, bool loadImp)
{
    if (ProjectModified)
    {
        int res = Application->MessageBox("Save active Project?", "Confirmation", MB_YESNOCANCEL | MB_ICONQUESTION);
        if (res == IDCANCEL) return;
        if (res == IDYES)
        {
            if (IDPFile == "") IDPFile = ChangeFileExt(SourceFile, ".idp");

            SaveDlg->InitialDir = WrkDir;
            SaveDlg->Filter = "IDP|*.idp";
            SaveDlg->FileName = IDPFile;

            if (SaveDlg->Execute()) SaveProject(SaveDlg->FileName);
        }
    }
    
    if (FileName == "")
    {
    	OpenDlg->InitialDir = WrkDir;
    	OpenDlg->FileName = "";
    	OpenDlg->Filter = "EXE, DLL|*.exe;*.dll|All files|*.*";
        if (OpenDlg->Execute()) FileName = OpenDlg->FileName;
    }
    if (FileName != "")
    {
        if (!FileExists(FileName))
        {
            //ShowMessage("File " + FileName + " not exists");
            LogMessage("File " + FileName + " not exists", MB_ICONERROR);
            return;
        }
        CloseProject();
        Init();
        idr.WrkDir = WrkDir = ExtractFileDir(FileName);
        LoadDelphiFile1(FileName, version, loadExp, loadImp);
    }
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::LoadDelphiFile1(String FileName, int version, bool loadExp, bool loadImp)
{
    int			pos, ver;
    String		dprName, KBFileName, msg;
    
    BusyCursor  cursor; //show busy cursor inside this routine, restore on exit
    
    SourceFile = FileName;

    int res = LoadImage(FileName, loadExp, loadImp);
    if (res <= 0) return;

    FindExports();
    FindImports();

    idr.ResInfo()->EnumResources(AppDir, SourceFile);
    idr.ResInfo()->ShowResources(lbForms);
    
    tsForms->Enabled = (lbForms->Items->Count > 0);

    if (version == DELHPI_VERSION_AUTO)   //Autodetect
    {
        DelphiVersion = GetDelphiVersion();
        if (DelphiVersion == -1)
        {
            LogMessage("File " + FileName + " is probably not Delphi file", MB_ICONWARNING);
            CleanProject();
            return;
        }
    }
    else
        DelphiVersion = version;

    UserKnowledgeBase = false;
    if (!quietMode
        && Application->MessageBox("Use native Knowledge Base?", "Knowledge Base kind selection", MB_YESNO | MB_ICONQUESTION) == IDNO)
    {
        OpenDlg->InitialDir = WrkDir;
    	OpenDlg->FileName = "";
    	OpenDlg->Filter = "BIN|*.bin|All files|*.*";
        if (OpenDlg->Execute())
        {
            KBFileName = OpenDlg->FileName;
            UserKnowledgeBase = true;
        }
    }
    else
        KBFileName = AppDir + "kb" + DelphiVersion + ".bin";

    if (KBFileName == "")
    {
        LogMessage("Knowledge Base file not selected", MB_ICONWARNING);
        CleanProject();
        return;
    }

    res = KnowledgeBase.Open(KBFileName.c_str());

    if (!res)
    {
        LogMessage("Cannot open Knowledge Base file " + KBFileName + " (may be incorrect Version)", MB_ICONWARNING);
        CleanProject();
        return;
    }

    Vmt.SetVmtConsts(DelphiVersion);
    InitSysProcs();

    dprName = ExtractFileName(FileName);
    pos = dprName.Pos(".");
    if (pos) dprName.SetLength(pos - 1);
    
    UnitsNum = GetUnits(dprName);

    if (UnitsNum > 0)
    {
        ShowUnits(false);
    }
    else
    {
        //May be BCB file?
        UnitsNum = GetBCBUnits(dprName);
        if (!UnitsNum)
        {
            LogMessage("Cannot find table of initialization and finalization procedures", MB_ICONWARNING);
            CleanProject();
            return;
        }
    }

    Caption = "Interactive Delphi Reconstructor (x64) by crypto and sendersu: "
        + SourceFile
        + " (Delphi-XE" + String(DelphiVersion - 2011) + ")";

    //Show code to allow user make something useful
    tsCodeView->Enabled = true;

    bEP->Enabled = true;
    //While loading file disable menu items
    miLoadFile->Enabled = false;
    miOpenProject->Enabled = false;
    miMRF->Enabled = false;
    miSaveProject->Enabled = false;
    miSaveDelphiProject->Enabled = false;
    lbCXrefs->Enabled = false;

    idr.WrkDir = WrkDir = ExtractFileDir(FileName);
    lbCode->ItemIndex = -1;

    //Fire all the code analysis in separate thread to make GUI alive & user happy! :)
    FProgressBar->Show();
    AnalyzeThread = new TAnalyzeThread(this->Handle, FProgressBar->Handle, true);
    AnalyzeThread->Resume();
}
//---------------------------------------------------------------------------
//Actions after analyzing
void __fastcall TFMain_11011981::AnalyzeThreadDone(TObject* Sender)
{
    if (!AnalyzeThread) return;

    AnalyzeThreadRetVal = AnalyzeThread->GetRetVal();
    if (AnalyzeThread->all && AnalyzeThreadRetVal >= LAST_ANALYZE_STEP)
    {
        ProjectLoaded = true;
        ProjectModified = true;
        AddExe2MRF(SourceFile);
    }

    //! does not work if main widow is minimized!
    // FProgressBar->Close();
    FProgressBar->Hide();
    
    //Restore menu items
    miLoadFile->Enabled = true;
    miOpenProject->Enabled = true;
    miMRF->Enabled = true;
    miSaveProject->Enabled = true;
    miSaveDelphiProject->Enabled = true;
    lbCXrefs->Enabled = true;

    miEditFunctionC->Enabled = true;
    miEditFunctionI->Enabled = true;
    miFuzzyScanKB->Enabled = true;
    miSearchItem->Enabled = true;
    miName->Enabled = true;
    miViewProto->Enabled = true;
    bDecompile->Enabled = true;

    miMapGenerator->Enabled = true;
    miCommentsGenerator->Enabled = true;
    miIDCGenerator->Enabled = true;
    miLister->Enabled = true;
    miKBTypeInfo->Enabled = true;
    miCtdPassword->Enabled = IsValidCodeAdr(CtdRegAdr);
    miHex2Double->Enabled = true;

    delete AnalyzeThread;
    AnalyzeThread = 0;
}
//---------------------------------------------------------------------------
bool __fastcall TFMain_11011981::ImportsValid(DWORD ImpRVA, DWORD ImpSize)
{
    if (ImpRVA || ImpSize)
    {
        DWORD EntryRVA = ImpRVA;
        DWORD EndRVA = ImpRVA + ImpSize;
        IMAGE_IMPORT_DESCRIPTOR ImportDescriptor;

        while (1)
        {
            memmove(&ImportDescriptor, (Image + Adr2Pos(EntryRVA + ImageBase)), sizeof(ImportDescriptor));

            if (!ImportDescriptor.OriginalFirstThunk &&
                !ImportDescriptor.TimeDateStamp &&
                !ImportDescriptor.ForwarderChain &&
                !ImportDescriptor.Name &&
                !ImportDescriptor.FirstThunk) break;

            if (!IsValidImageAdr(ImportDescriptor.Name + ImageBase)) return false;
            int NameLength = strlen((char*)(Image + Adr2Pos(ImportDescriptor.Name + ImageBase)));
            if (NameLength < 0 || NameLength > 256) return false;
            if (!IsValidModuleName(NameLength, Adr2Pos(ImportDescriptor.Name + ImageBase))) return false;

            EntryRVA += sizeof(ImportDescriptor);
            if (EntryRVA >= EndRVA) break;
        }
    }
    return true;
}
//---------------------------------------------------------------------------
int __fastcall TFMain_11011981::LoadImage(String imageFile, bool loadExp, bool loadImp)
{
    BYTE                    op;
    int         	        i, n, m, bytes, pos, SectionsNum, ExpNum, NameLength, InstrLen;
    DWORD       	        DataEnd, Items;
    String      	        moduleName, modName, sEP;
    String      	        impFuncName;
    IMAGE_DOS_HEADER        DosHeader;
    IMAGE_NT_HEADERS64      NTHeaders;
    PIMAGE_SECTION_HEADER   SectionHeaders=0;
    DISINFO                 DisInfo;
    char                    segname[9];
    char                    msg[1024];
    FILE                    *f=0;
    Image = 0;

    try
    {
        FILE *f = fopen(imageFile.c_str(), "rb");
        if (0 == f)
        {
            throw Exception("Can't open image file "+imageFile);
        }

        fseek(f, 0L, SEEK_SET);
        //IDD_ERR_NOT_EXECUTABLE
        if (fread(&DosHeader, 1, sizeof(IMAGE_DOS_HEADER), f) != sizeof(IMAGE_DOS_HEADER) ||
            DosHeader.e_magic != IMAGE_DOS_SIGNATURE)
        {
            throw Exception("File is not executable");
        }

        int r = fseek(f, DosHeader.e_lfanew, SEEK_SET);
        //IDD_ERR_NOT_PE_EXECUTABLE
        if (fread(&NTHeaders, 1, sizeof(IMAGE_NT_HEADERS), f) != sizeof(IMAGE_NT_HEADERS) ||
            NTHeaders.Signature != IMAGE_NT_SIGNATURE)
        {
            throw Exception("File is not PE-executable");
        }
        //IDD_ERR_INVALID_PE_EXECUTABLE
        if (NTHeaders.FileHeader.SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER) ||
            NTHeaders.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        {
            throw Exception("File is invalid 64-bit PE-executable");
        }
        //IDD_ERR_INVALID_PE_EXECUTABLE
        SectionsNum = NTHeaders.FileHeader.NumberOfSections;
        if (!SectionsNum)
        {
            throw Exception("File is invalid PE-executable (0 sections)");
        }
        //SizeOfOptionalHeader may be > than sizeof(IMAGE_OPTIONAL_HEADER)
        fseek(f, NTHeaders.FileHeader.SizeOfOptionalHeader - sizeof(IMAGE_OPTIONAL_HEADER), SEEK_CUR);
        SectionHeaders = new IMAGE_SECTION_HEADER[SectionsNum];

        if (fread(SectionHeaders, 1, sizeof(IMAGE_SECTION_HEADER)*SectionsNum, f) !=
            sizeof(IMAGE_SECTION_HEADER)*SectionsNum)
        {
            throw Exception("Invalid section headers");
        }

        ImageBase = NTHeaders.OptionalHeader.ImageBase;
        ImageSize = NTHeaders.OptionalHeader.SizeOfImage;
        EP = NTHeaders.OptionalHeader.AddressOfEntryPoint;

        TotalSize = 0;
        DWORD rsrcVA = NTHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress;
        DWORD relocVA = NTHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
        //Fill SegmentList
        for (i = 0; i < SectionsNum; i++)
        {
            PSegmentInfo segInfo = new SegmentInfo;
            segInfo->Start = SectionHeaders[i].VirtualAddress + ImageBase;
            segInfo->Flags = SectionHeaders[i].Characteristics;

            if (i + 1 < SectionsNum)
                segInfo->Size = SectionHeaders[i + 1].VirtualAddress - SectionHeaders[i].VirtualAddress;
            else
                segInfo->Size = SectionHeaders[i].Misc.VirtualSize;

            if (!SectionHeaders[i].SizeOfRawData)//uninitialized data
            {
                //segInfo->Size = SectionHeaders[i].Misc.VirtualSize;
                segInfo->Flags |= 0x80000;
            }
            else if (SectionHeaders[i].VirtualAddress == rsrcVA || SectionHeaders[i].VirtualAddress == relocVA)
            {
                //segInfo->Size = SectionHeaders[i].SizeOfRawData;
                segInfo->Flags |= 0x80000;
            }
            else
            {
                //segInfo->Size = SectionHeaders[i].SizeOfRawData;
                TotalSize += segInfo->Size;
            }
            memset(segname, 0, 9);
            memmove(segname, SectionHeaders[i].Name, 8);
            segInfo->Name = String(segname);
            SegmentList->Add((void*)segInfo);
        }
        //DataEnd = TotalSize;

        //Load Image into memory
        Image = new BYTE[TotalSize];
        memset((void*)Image, 0, TotalSize);
        int num;
        BYTE *p = Image;
        for (i = 0; i < SectionsNum; i++)
        {
            if (SectionHeaders[i].VirtualAddress == rsrcVA || SectionHeaders[i].VirtualAddress == relocVA) continue;
            BYTE *sp = p;
            fseek(f, SectionHeaders[i].PointerToRawData, SEEK_SET);
            DWORD Items = SectionHeaders[i].SizeOfRawData;
            if (Items)
            {
                for (n = 0; Items >= MAX_ITEMS; n++)
                {
                    fread(p, 1, MAX_ITEMS, f);
                    Items -= MAX_ITEMS;
                    p += MAX_ITEMS;
                }
                if (Items)
                {
                    fread(p, 1, Items, f);
                    p += Items;
                }
                num = p - Image;
                if (i + 1 < SectionsNum)
                    p = sp + (SectionHeaders[i + 1].VirtualAddress - SectionHeaders[i].VirtualAddress);
            }
        }

        CodeStart = 0;
        Code = Image + CodeStart;
        CodeBase = ImageBase + SectionHeaders[0].VirtualAddress;

        InitTable = EvaluateInitTable(Image, TotalSize, CodeBase);
        if (!InitTable)
        {
            throw Exception("Cannot find initialization table");
        }

        DWORD evalEP = 0;
        //Find instruction lea reg,offset InitTable
        for (n = 0; n < TotalSize - 7; n++)
        {
            if (Image[n] == 0x48 &&     //64-bit Operand size
                Image[n + 1] == 0x8D && //lea
                *((DWORD*)(Image + n + 3)) + CodeBase + n + 7 == InitTable) //Offset rel next instruction
            {
                evalEP = n;
                break;
            }
        }
        //Scan up until bytes 0x55 (push rbp) and 0x48
        if (evalEP)
        {
            while (evalEP != 0)
            {
                if (Image[evalEP] == 0x55 && Image[evalEP + 1] == 0x48)
                    break;
                evalEP--;
            }
        }
        //Check evalEP
        if (evalEP + CodeBase != NTHeaders.OptionalHeader.AddressOfEntryPoint + ImageBase)
        {
            sprintf(msg, "Possible invalid EP (NTHeader:%lX, Evaluated:%lX). Input valid EP?", NTHeaders.OptionalHeader.AddressOfEntryPoint + ImageBase, evalEP + CodeBase);
            if (Application->MessageBox(msg, "Confirmation", MB_YESNO | MB_ICONQUESTION) == IDYES)
            {
                sEP = InputDialogExec("New EP", "EP:", Val2Str0(NTHeaders.OptionalHeader.AddressOfEntryPoint + ImageBase));
                if (sEP != "")
                {
                    sscanf(sEP.c_str(), "%lX", &EP);
                    if (!IsValidImageAdr(EP))
                    {
                        throw Exception("Invalid address: "+sEP);
                    }
                }
                else
                {
                    throw Exception("Invalid address: "+sEP);
                }
            }
            else
            {
                throw Exception("OK");
            }
        }
        else
        {
            EP = NTHeaders.OptionalHeader.AddressOfEntryPoint + ImageBase;
        }
        //Find DataStart
        //DWORD _codeEnd = DataEnd;
        //DataStart = CodeStart;
        //for (i = 0; i < SectionsNum; i++)
        //{
        //    if (SectionHeaders[i].VirtualAddress + ImageBase > EP)
        //    {
        //        _codeEnd = SectionHeaders[i].VirtualAddress;
        //        DataStart = SectionHeaders[i].VirtualAddress;
        //        break;
        //    }
        //}
        delete[] SectionHeaders;

        CodeSize = TotalSize;//_codeEnd - SectionHeaders[0].VirtualAddress;
        //DataSize = DataEnd - DataStart;
        //DataBase = ImageBase + DataStart;

        idr.CreateDBs(TotalSize);

        if (loadExp)
        {
            //Load Exports
            DWORD ExpRVA = NTHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
            //DWORD ExpSize = NTHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

            if (ExpRVA)
            {
                IMAGE_EXPORT_DIRECTORY ExportDescriptor;
                memmove(&ExportDescriptor, (Image + Adr2Pos(ExpRVA + ImageBase)), sizeof(IMAGE_EXPORT_DIRECTORY));
                ExpNum = ExportDescriptor.NumberOfFunctions;
                DWORD ExpFuncNamPos = ExportDescriptor.AddressOfNames;
                DWORD ExpFuncAdrPos = ExportDescriptor.AddressOfFunctions;
                DWORD ExpFuncOrdPos = ExportDescriptor.AddressOfNameOrdinals;

                for (i = 0; i < ExpNum; i++)
                {
                    PExportNameRec recE = new ExportNameRec;

                    DWORD dp = *((DWORD*)(Image + Adr2Pos(ExpFuncNamPos + ImageBase)));
                    NameLength = strlen((char*)(Image + Adr2Pos(dp + ImageBase)));
                    recE->name = String((char*)(Image + Adr2Pos(dp + ImageBase)), NameLength);

                    WORD dw = *((WORD*)(Image + Adr2Pos(ExpFuncOrdPos + ImageBase)));
                    recE->address = *((DWORD*)(Image + Adr2Pos(ExpFuncAdrPos + 4*dw + ImageBase))) + ImageBase;
                    recE->ord = dw + ExportDescriptor.Base;
                    ExpFuncList->Add((void*)recE);

                    ExpFuncNamPos += 4;
                    ExpFuncOrdPos += 2;
                }
                ExpFuncList->Sort(ExportsCmpFunction);
            }
        }

        DWORD	ImpRVA = NTHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        DWORD	ImpSize = NTHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;

        if (loadImp && (ImpRVA || ImpSize))
        {
            if (!ImportsValid(ImpRVA, ImpSize))
            {
                //ShowMessage("Imports not valid, will skip!");
                LogMessage("Imports not valid, will skip!", MB_ICONWARNING);
            }
            else
            {
                //Load Imports
                DWORD	EntryRVA;		//Next import decriptor RVA
                DWORD   EndRVA;         //End of imports
                DWORD	ThunkRVA;		//RVA of next thunk (from FirstThunk)
                DWORD	LookupRVA;		//RVA of next thunk (from OriginalFirstTunk or FirstThunk)
                DWORD	ThunkValue;		//Value of next thunk (from OriginalFirstTunk or FirstThunk)
                WORD	Hint;			//Ordinal or hint of imported symbol

                IMAGE_IMPORT_DESCRIPTOR ImportDescriptor;

                //DWORD fnProc = 0;

                //First import descriptor
                EntryRVA = ImpRVA;
                EndRVA = ImpRVA + ImpSize;

                while (1)
                {
                    memmove(&ImportDescriptor, (Image + Adr2Pos(EntryRVA + ImageBase)), sizeof(IMAGE_IMPORT_DESCRIPTOR));
                    //All descriptor fields are NULL - end of list, break
                    if (!ImportDescriptor.OriginalFirstThunk &&
                        !ImportDescriptor.TimeDateStamp &&
                        !ImportDescriptor.ForwarderChain &&
                        !ImportDescriptor.Name &&
                        !ImportDescriptor.FirstThunk) break;

                    NameLength = strlen((char*)(Image + Adr2Pos(ImportDescriptor.Name + ImageBase)));
                    moduleName = String((char*)(Image + Adr2Pos(ImportDescriptor.Name + ImageBase)), NameLength);

                    int pos = moduleName.Pos(".");
                    if (pos)
                        modName = moduleName.SubString(1, pos - 1);
                    else
                        modName = moduleName;

                    if (-1 == ImpModuleList->IndexOf(moduleName))
                        ImpModuleList->Add(moduleName);

                    //HINSTANCE hLib = LoadLibraryEx(moduleName.c_str(), 0, LOAD_LIBRARY_AS_DATAFILE);

                    //Define the source of import names (OriginalFirstThunk or FirstThunk)
                    if (ImportDescriptor.OriginalFirstThunk)
                        LookupRVA = ImportDescriptor.OriginalFirstThunk;
                    else
                        LookupRVA = ImportDescriptor.FirstThunk;

                    // ThunkRVA get from FirstThunk always
                    ThunkRVA = ImportDescriptor.FirstThunk;
                    //Get Imported Functions
                    while (1)
                    {
                        //Names or ordinals get from LookupTable (this table can be inside OriginalFirstThunk or FirstThunk)
                        ThunkValue = *((DWORD*)(Image + Adr2Pos(LookupRVA + ImageBase)));
                        if (!ThunkValue) break;

                        //fnProc = 0;
                        PImportNameRec recI = new ImportNameRec;

                        if (ThunkValue & 0x80000000)
                        {
                            //By ordinal
                            Hint = (WORD)(ThunkValue & 0xFFFF);

                            //if (hLib) fnProc = (DWORD)GetProcAddress(hLib, (char*)Hint);

                            //Addresse get from FirstThunk only
                            //recI->name = modName + "." + String(Hint);
                            recI->name = String(Hint);
                        }
                        else
                        {
                            // by name
                            Hint = *((WORD*)(Image + Adr2Pos(ThunkValue + ImageBase)));
                            NameLength = lstrlen((char*)(Image + Adr2Pos(ThunkValue + 2 + ImageBase)));
                            impFuncName = "__imp_" + String((char*)(Image + Adr2Pos(ThunkValue + 2 + ImageBase)), NameLength);

                            //if (hLib)
                            //{
                            //    fnProc = (DWORD)GetProcAddress(hLib, impFuncName.c_str());
                            //    memmove((void*)(Image + ThunkRVA), (void*)&fnProc, sizeof(DWORD));
                            //}

                            recI->name = impFuncName;
                        }
                        recI->module = modName;
                        recI->address = ImageBase + ThunkRVA;
                        ImpFuncList->Add((void*)recI);
                        //
                        idr.SetFlag(cfImport, Adr2Pos(recI->address));
                        PInfoRec recN = new InfoRec(Adr2Pos(recI->address), ikData);
                        recN->SetName(impFuncName);
                        //
                        ThunkRVA += 8;
                        LookupRVA += 8;
                    }
                    EntryRVA += sizeof(IMAGE_IMPORT_DESCRIPTOR);
                    if (EntryRVA >= EndRVA) break;

                    //if (hLib)
                    //{
                    //    FreeLibrary(hLib);
                    //    hLib = NULL;
                    //}
                }
                ImpFuncList->Sort(ImportsCmpFunction);
            }
        }
        //Exception Directory
        DWORD	ExcRVA = NTHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress;
        DWORD	ExcSize = NTHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size;
        int ExcNum = ExcSize / 12;  //12 = sizeof(RUNTIME_FUNCTION)
        for (n = 0; n < ExcNum; n++, ExcRVA += 12)
        {
            DWORD FunctionStart = *((DWORD*)(Image + Adr2Pos(ExcRVA + ImageBase)));
            DWORD FunctionEnd = *((DWORD*)(Image + Adr2Pos(ExcRVA + ImageBase + 4)));
            idr.SetFlag(cfProcStart | cfExcInfo, Adr2Pos(ImageBase + FunctionStart));
            idr.SetFlag(cfProcEnd, Adr2Pos(ImageBase + FunctionEnd));
        }

        fclose(f);

    }
    catch(const Exception& ex)
    {
        LogMessage(ex.Message, MB_ICONERROR);

        if (f)
            fclose(f);
        if (SectionHeaders)
            delete[] SectionHeaders;
        if (Image)
            delete[] Image;
        Image = 0;

        return 0;
    }


    //we are cool
    return 1;
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::miOpenProjectClick(TObject *Sender)
{
	DoOpenProjectFile("");
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::DoOpenProjectFile(String FileName)
{
    char		    *buf;
    int			    n, m, num, len, size, pos;
    PInfoRec        recN;
    PUnitRec	    recU;
    PTypeRec    recT;
    PFIELDINFO      fInfo;

    if (ProjectModified)
    {
        int res = Application->MessageBox("Save active Project?", "Confirmation", MB_YESNOCANCEL | MB_ICONQUESTION);
        if (res == IDCANCEL) return;
        if (res == IDYES)
        {
            if (IDPFile == "") IDPFile = ChangeFileExt(SourceFile, ".idp");

            SaveDlg->InitialDir = WrkDir;
            SaveDlg->Filter = "IDP|*.idp";
            SaveDlg->FileName = IDPFile;

            if (SaveDlg->Execute()) SaveProject(SaveDlg->FileName);
        }
    }
    if (FileName == "")
    {
    	OpenDlg->InitialDir = WrkDir;
    	OpenDlg->FileName = "";
    	OpenDlg->Filter = "IDP|*.idp";
    	if (OpenDlg->Execute()) FileName = OpenDlg->FileName;
    }
    if (FileName != "")
    {
        if (!FileExists(FileName))
        {
            //ShowMessage("File " + FileName + " not exists");
            LogMessage("File " + FileName + " not exists", MB_ICONWARNING);
            return;
        }
        CloseProject();
        Init();
        idr.WrkDir = WrkDir = ExtractFileDir(FileName);
        OpenProject(FileName);
    }
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::ReadNode(TStream* stream, TTreeNode* node, char* buf)
{
    //Count
    int itemsCount;
    stream->Read(&itemsCount, sizeof(itemsCount));

    //Text
    int len;
    stream->Read(&len, sizeof(len));
    stream->Read(buf, len);
    node->Text = String(buf, len);
    FProgressBar->pb->StepIt();

    for (int n = 0; n < itemsCount; n++)
    {
        TTreeNode* snode = node->Owner->AddChild(node, "");
        ReadNode(stream, snode, buf);
    }
    Application->ProcessMessages();
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::OpenProject(String FileName)
{
    bool        _useFuzzy = true;
    BYTE        _idpver;
    int         n, m, k, u, pos, len, num, cnum, evnum, size, infosCnt, bssCnt, _ver;
    int         topIdxU, itemIdxU, topIdxI, itemIdxI, topIdxC;
    String      KBFileName;
    PInfoRec    recN;

    BusyCursor  cursor;
    
    IDPFile = FileName;

    FILE* projectFile = fopen(FileName.c_str(), "rb");

    fseek(projectFile, IDPMAGICLEN, SEEK_SET);
    //Read idp project version
    fread(&_idpver, sizeof(_idpver), 1, projectFile);
    //Read Delphi version and maximum length of buffer
    fread(&_ver, sizeof(_ver), 1, projectFile);

    DelphiVersion = _ver & ~(USER_KNOWLEDGEBASE | SOURCE_LIBRARY);
    UserKnowledgeBase = false;
    SourceIsLibrary = (_ver & SOURCE_LIBRARY);
    if (_ver & USER_KNOWLEDGEBASE)
    {
        //ShowMessage("Choose original Knowledge Base");
        LogMessage("Choose original Knowledge Base", MB_ICONWARNING);
        OpenDlg->InitialDir = WrkDir;
    	OpenDlg->FileName = "";
    	OpenDlg->Filter = "BIN|*.bin|All files|*.*";
        if (OpenDlg->Execute())
        {
            KBFileName = OpenDlg->FileName;
            UserKnowledgeBase = true;
        }
        else
        {
            //ShowMessage("Native Knowledge Base will be used!");
            LogMessage("Native Knowledge Base will be used!", MB_ICONINFORMATION);
            _useFuzzy = false;
        }
    }
    if (!UserKnowledgeBase) KBFileName = AppDir + "kb" + DelphiVersion + ".bin";
    
    MaxBufLen = 0;
    fseek(projectFile, -4L, SEEK_END);
    fread(&MaxBufLen, sizeof(MaxBufLen), 1, projectFile);
    fclose(projectFile);

    if (!KnowledgeBase.Open(KBFileName.c_str()))
    {
        //ShowMessage("Cannot open KnowledgeBase (may be incorrect Version)");
        LogMessage("Cannot open KnowledgeBase (may be incorrect Version):"+KBFileName, MB_ICONWARNING);
        return;
    }

    Caption = "Interactive Delphi Reconstructor (64bit) by crypto and sendersu: " + IDPFile + " (D" + DelphiVersion + ")";

    Vmt.SetVmtConsts(DelphiVersion);

    //Disable menu items
    miLoadFile->Enabled = false;
    miOpenProject->Enabled = false;
    miMRF->Enabled = false;
    miSaveProject->Enabled = false;
    miSaveDelphiProject->Enabled = false;
    lbCXrefs->Enabled = false;

    Update();

    char* buf = new BYTE[MaxBufLen];
    TMemoryStream* inStream = new TMemoryStream();
    inStream->LoadFromFile(IDPFile);

    char magic[IDPMAGICLEN];
    inStream->Read(magic, IDPMAGICLEN);
    inStream->Read(&_idpver, sizeof(_idpver));
    inStream->Read(&_ver, sizeof(_ver));
    DelphiVersion = _ver & ~(USER_KNOWLEDGEBASE | SOURCE_LIBRARY);

    inStream->Read(&EP, sizeof(EP));
    inStream->Read(&ImageBase, sizeof(ImageBase));
    inStream->Read(&ImageSize, sizeof(ImageSize));
    inStream->Read(&TotalSize, sizeof(TotalSize));
    inStream->Read(&CodeBase, sizeof(CodeBase));
    inStream->Read(&CodeSize, sizeof(CodeSize));
    inStream->Read(&CodeStart, sizeof(CodeStart));

    inStream->Read(&DataBase, sizeof(DataBase));
    inStream->Read(&DataSize, sizeof(DataSize));
    inStream->Read(&DataStart, sizeof(DataStart));
    

    //SegmentList
    inStream->Read(&num, sizeof(num));
    for (n = 0; n < num; n++)
    {
        PSegmentInfo segInfo = new SegmentInfo;
        inStream->Read(&segInfo->Start, sizeof(segInfo->Start));
        inStream->Read(&segInfo->Size, sizeof(segInfo->Size));
        inStream->Read(&segInfo->Flags, sizeof(segInfo->Flags));
        inStream->Read(&len, sizeof(len));
        inStream->Read(buf, len);
        segInfo->Name = String(buf, len);
        SegmentList->Add((void*)segInfo);
    }

    Image = new BYTE[TotalSize];
    Code = Image + CodeStart;
    Data = Image + DataStart;
    DWORD Items = TotalSize;
    BYTE* pImage = Image;

    while (Items >= MAX_ITEMS)
    {
        inStream->Read(pImage, MAX_ITEMS);
        pImage += MAX_ITEMS;
        Items -= MAX_ITEMS;
    }
    if (Items) inStream->Read(pImage, Items);

    idr.CreateDBs(TotalSize);

    Items = TotalSize;
    DWORD* pFlags = idr.Flags;

    while (Items >= MAX_ITEMS)
    {
        inStream->Read(pFlags, sizeof(DWORD)*MAX_ITEMS);
        pFlags += MAX_ITEMS;
        Items -= MAX_ITEMS;
    }
    if (Items) inStream->Read(pFlags, sizeof(DWORD)*Items);

    inStream->Read(&infosCnt, sizeof(infosCnt));
    BYTE kind;
    for (n = 0; n < TotalSize; n++)
    {
        inStream->Read(&pos, sizeof(pos));
        if (pos == -1) break;
        inStream->Read(&kind, sizeof(kind));
        recN = new InfoRec(pos, kind);
        recN->Load(inStream, buf);
    }
    //BSSInfos
    ///BSSInfos = new TStringList;
    inStream->Read(&bssCnt, sizeof(bssCnt));
    for (n = 0; n < bssCnt; n++)
    {
        inStream->Read(&len, sizeof(len));
        inStream->Read(buf, len);
        String _adr = String(buf, len);
        inStream->Read(&kind, sizeof(kind));
        recN = new InfoRec(-1, kind);
        recN->Load(inStream, buf);

        idr.BSSInfosAddObject(_adr, recN);
    }
    ///BSSInfos->Sorted = true;

    lbCXrefs->Enabled = true;

    //Units
    inStream->Read(&num, sizeof(num));

    UnitsNum = num;
    for (n = 0; n < UnitsNum; n++)
    {
        PUnitRec recU = new UnitRec;
        inStream->Read(&recU->trivial, sizeof(recU->trivial));
        inStream->Read(&recU->trivialIni, sizeof(recU->trivialIni));
        inStream->Read(&recU->trivialFin, sizeof(recU->trivialFin));
        inStream->Read(&recU->kb, sizeof(recU->kb));
        inStream->Read(&recU->fromAdr, sizeof(recU->fromAdr));
        inStream->Read(&recU->toAdr, sizeof(recU->toAdr));
        inStream->Read(&recU->finadr, sizeof(recU->finadr));
        inStream->Read(&recU->finSize, sizeof(recU->finSize));
        inStream->Read(&recU->iniadr, sizeof(recU->iniadr));
        inStream->Read(&recU->iniSize, sizeof(recU->iniSize));
        recU->matchedPercent = 0.0;
        inStream->Read(&recU->iniOrder, sizeof(recU->iniOrder));
        recU->names = new TStringList;
        int namesNum = 0;
        inStream->Read(&namesNum, sizeof(namesNum));
        for (u = 0; u < namesNum; u++)
        {
            inStream->Read(&len, sizeof(len));
            inStream->Read(buf, len);
            SetUnitName(recU, String(buf, len));
        }
        Units->Add((void*)recU);
    }
    UnitSortField = 0;
    CurUnitAdr = 0;
    topIdxU = 0; itemIdxU = -1;
    topIdxI = 0; itemIdxI = -1;

    if (UnitsNum)
    {
        inStream->Read(&UnitSortField, sizeof(UnitSortField));
        inStream->Read(&CurUnitAdr, sizeof(CurUnitAdr));
        inStream->Read(&topIdxU, sizeof(topIdxU));
        inStream->Read(&itemIdxU, sizeof(itemIdxU));
        //UnitItems
        if (CurUnitAdr)
        {
      	  	inStream->Read(&topIdxI, sizeof(topIdxI));
        	inStream->Read(&itemIdxI, sizeof(itemIdxI));
        }
    }

    tsUnits->Enabled = true;
    switch (UnitSortField)
    {
    case 0:
        miSortUnitsByAdr->Checked = true;
        miSortUnitsByOrd->Checked = false;
        miSortUnitsByNam->Checked = false;
        break;
    case 1:
        miSortUnitsByAdr->Checked = false;
        miSortUnitsByOrd->Checked = true;
        miSortUnitsByNam->Checked = false;
        break;
    case 2:
        miSortUnitsByAdr->Checked = false;
        miSortUnitsByOrd->Checked = false;
        miSortUnitsByNam->Checked = true;
        break;
    }
    ShowUnits(true);
    lbUnits->TopIndex = topIdxU;
    lbUnits->ItemIndex = itemIdxU;

    ShowUnitItems(GetUnit(CurUnitAdr), topIdxI, itemIdxI);

    miRenameUnit->Enabled = true;
    miSearchUnit->Enabled = true;
    miSortUnits->Enabled = true;
    miCopyList->Enabled = true;

    miEditFunctionC->Enabled = true;
    miEditFunctionI->Enabled = true;
    miFuzzyScanKB->Enabled = true;
    miSearchItem->Enabled = true;

    //Types
    inStream->Read(&num, sizeof(num));
    for (n = 0; n < num; n++)
    {
        PTypeRec recT = new TypeRec;
        inStream->Read(&recT->kind, sizeof(recT->kind));
        inStream->Read(&recT->adr, sizeof(recT->adr));
        inStream->Read(&len, sizeof(len));
        inStream->Read(buf, len);
        recT->name = String(buf, len);
        OwnTypeList->Add((void*)recT);
    }
    RTTISortField = 0;
    if (num) inStream->Read(&RTTISortField, sizeof(RTTISortField));
    //UpdateRTTIs
    tsRTTIs->Enabled = true;
    miSearchRTTI->Enabled = true;
    miSortRTTI->Enabled = true;

    switch (RTTISortField)
    {
    case 0:
        miSortRTTIsByAdr->Checked = true;
        miSortRTTIsByKnd->Checked = false;
        miSortRTTIsByNam->Checked = false;
        break;
    case 1:
        miSortRTTIsByAdr->Checked = false;
        miSortRTTIsByKnd->Checked = true;
        miSortRTTIsByNam->Checked = false;
        break;
    case 2:
        miSortRTTIsByAdr->Checked = false;
        miSortRTTIsByKnd->Checked = false;
        miSortRTTIsByNam->Checked = true;
        break;
    }
    ShowRTTIs();

    //Forms
    inStream->Read(&num, sizeof(num));
    for (n = 0; n < num; n++)
    {
        TDfm* dfm = new TDfm;
        //Flags
        inStream->Read(&dfm->Flags, sizeof(dfm->Flags));
        //ResName
        inStream->Read(&len, sizeof(len));
        inStream->Read(buf, len);
        dfm->ResName = String(buf, len);
        //Name
        inStream->Read(&len, sizeof(len));
        inStream->Read(buf, len);
        dfm->Name = String(buf, len);
        //ClassName
        inStream->Read(&len, sizeof(len));
        inStream->Read(buf, len);
        dfm->ClassName = String(buf, len);
        //MemStream
        inStream->Read(&size, sizeof(size));
        dfm->MemStream->Size = size;
        while (size >= 4096)
        {
            inStream->Read(buf, 4096);
            dfm->MemStream->Write(buf, 4096);
            size -= 4096;
        }
        if (size)
        {
            inStream->Read(buf, size);
            dfm->MemStream->Write(buf, size);
        }
        //Events
        dfm->Events = new TList;
        inStream->Read(&evnum, sizeof(evnum));
        for (m = 0; m < evnum; m++)
        {
            PEventInfo eInfo = new EventInfo;
            //EventName
            inStream->Read(&len, sizeof(len));
            inStream->Read(buf, len);
            eInfo->EventName = String(buf, len);
            //ProcName
            inStream->Read(&len, sizeof(len));
            inStream->Read(buf, len);
            eInfo->ProcName = String(buf, len);
            dfm->Events->Add((void*)eInfo);
        }
        //Components
        inStream->Read(&cnum, sizeof(cnum));
        if (cnum)
        {
        	dfm->Components = new TList;
            for (m = 0; m < cnum; m++)
            {
                PComponentInfo cInfo = new ComponentInfo;
                //Inherited
                inStream->Read(&cInfo->Inherit, sizeof(cInfo->Inherit));
                //HasGlyph
                inStream->Read(&cInfo->HasGlyph, sizeof(cInfo->HasGlyph));
                //Name
                inStream->Read(&len, sizeof(len));
                inStream->Read(buf, len);
                cInfo->Name = String(buf, len);
                //ClassName
                inStream->Read(&len, sizeof(len));
                inStream->Read(buf, len);
                cInfo->ClassName = String(buf, len);
                //Events
                cInfo->Events = new TList;
                inStream->Read(&evnum, sizeof(evnum));
                for (k = 0; k < evnum; k++)
                {
                    PEventInfo eInfo = new EventInfo;
                    //EventName
                    inStream->Read(&len, sizeof(len));
                    inStream->Read(buf, len);
                    eInfo->EventName = String(buf, len);
                    //ProcName
                    inStream->Read(&len, sizeof(len));
                    inStream->Read(buf, len);
                    eInfo->ProcName = String(buf, len);
                    cInfo->Events->Add((void*)eInfo);
                }
                dfm->Components->Add((void*)cInfo);
            }
        }
        idr.ResInfo()->AddDfm(dfm);
    }
    //UpdateForms
    idr.ResInfo()->ShowResources(lbForms);
    
    //Aliases
    inStream->Read(&num, sizeof(num));
    for (n = 0; n < num; n++)
    {
        inStream->Read(&len, sizeof(len));
        inStream->Read(buf, len);
        idr.ResInfo()->AddAlias(String(buf, len));
    }
    InitAliases(false);
    tsForms->Enabled = (lbForms->Items->Count > 0);

    //CodeHistory
    inStream->Read(&CodeHistorySize, sizeof(CodeHistorySize));
    inStream->Read(&CodeHistoryPtr, sizeof(CodeHistoryPtr));
    inStream->Read(&CodeHistoryMax, sizeof(CodeHistoryMax));
    bCodePrev->Enabled = (CodeHistoryPtr >= 0);
    bCodeNext->Enabled = (CodeHistoryPtr < CodeHistoryMax);

    CodeHistory.Length = CodeHistorySize;
    for (n = 0; n < CodeHistorySize; n++)
        inStream->Read(&CodeHistory[n], sizeof(PROCHISTORYREC));

    inStream->Read(&CurProcAdr, sizeof(CurProcAdr));
    inStream->Read(&topIdxC, sizeof(topIdxC));

    //Important variables
    inStream->Read(&HInstanceVarAdr, sizeof(HInstanceVarAdr));
    inStream->Read(&LastTls, sizeof(LastTls));

    inStream->Read(&Reserved, sizeof(Reserved));
    inStream->Read(&LastResStrNo, sizeof(LastResStrNo));

	inStream->Read(&CtdRegAdr, sizeof(CtdRegAdr));

    //UpdateVmtList
    FillVmtList();
    //UpdateCode
    tsCodeView->Enabled = true;
    miGoTo->Enabled = true;
    miExploreAdr->Enabled = true;
    miSwitchFlag->Enabled = cbMultipleSelection->Checked;
    bEP->Enabled = true;
    DWORD adr = CurProcAdr;
    CurProcAdr = 0;
    ShowCode(adr, 0, -1, topIdxC);
    //UpdateStrings
    tsStrings->Enabled = true;
    miSearchString->Enabled = true;
    ShowStrings(0);
    //UpdateNames
    tsNames->Enabled = true;
    ShowNames(0);

    Update();

    //Class Viewer
    //Total nodes num (for progress bar)
    int nodesNum;
    inStream->Read(&nodesNum, sizeof(nodesNum));
    if (nodesNum)
    {
        tvClassesFull->Items->BeginUpdate();
        TTreeNode* root = tvClassesFull->Items->Add(0, "");
        ReadNode(inStream, root, buf);
        tvClassesFull->Items->EndUpdate();
        ClassTreeDone = true;
    }
    //UpdateClassViewer
    tsClassView->Enabled = true;
    miViewClass->Enabled = true;
    miSearchVMT->Enabled = true;
    miCollapseAll->Enabled = true;
    miEditClass->Enabled = true;

    if (ClassTreeDone)
    {
        TTreeNode *root = tvClassesFull->Items->Item[0];
        root->Expanded = true;
        rgViewerMode->ItemIndex = 0;
        rgViewerMode->Enabled = true;
        tvClassesFull->BringToFront();
    }
    else
    {
        rgViewerMode->ItemIndex = 1;
        rgViewerMode->Enabled = false;
        tvClassesShort->BringToFront();
    }
    miClassTreeBuilder->Enabled = true;

    //Just cheking
    inStream->Read(&MaxBufLen, sizeof(MaxBufLen));

    if (buf) delete[] buf;
    delete inStream;

    ProjectLoaded = true;
    ProjectModified = false;

    AddIdp2MRF(FileName);

    //Enable lemu items
    miLoadFile->Enabled = true;
    miOpenProject->Enabled = true;
    miMRF->Enabled = true;
    miSaveProject->Enabled = true;
    miSaveDelphiProject->Enabled = true;

    miEditFunctionC->Enabled = true;
    miEditFunctionI->Enabled = true;
    miFuzzyScanKB->Enabled = _useFuzzy;
    miSearchItem->Enabled = true;
    miName->Enabled = true;
    miViewProto->Enabled = true;
    bDecompile->Enabled = true;

    miMapGenerator->Enabled = true;
    miCommentsGenerator->Enabled = true;
    miIDCGenerator->Enabled = true;
    miLister->Enabled = true;
    miKBTypeInfo->Enabled = true;
    miCtdPassword->Enabled = IsValidCodeAdr(CtdRegAdr);
    miHex2Double->Enabled = true;

    idr.WrkDir = WrkDir = ExtractFileDir(FileName);
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::miExe1Click(TObject *Sender)
{
    LoadFile(miExe1->Caption, miMRF->Items[0]->Tag);
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::miExe2Click(TObject *Sender)
{
    LoadFile(miExe2->Caption, miMRF->Items[1]->Tag);
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::miExe3Click(TObject *Sender)
{
    LoadFile(miExe3->Caption, miMRF->Items[2]->Tag);
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::miExe4Click(TObject *Sender)
{
    LoadFile(miExe4->Caption, miMRF->Items[3]->Tag);
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::miExe5Click(TObject *Sender)
{
    LoadFile(miExe5->Caption, miMRF->Items[4]->Tag);
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::miExe6Click(TObject *Sender)
{
    LoadFile(miExe6->Caption, miMRF->Items[5]->Tag);
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::miExe7Click(TObject *Sender)
{
    LoadFile(miExe7->Caption, miMRF->Items[6]->Tag);
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::miExe8Click(TObject *Sender)
{
    LoadFile(miExe8->Caption, miMRF->Items[7]->Tag);
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::miIdp1Click(TObject *Sender)
{
    LoadFile(miIdp1->Caption, -1);
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::miIdp2Click(TObject *Sender)
{
    LoadFile(miIdp2->Caption, -1);
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::miIdp3Click(TObject *Sender)
{
    LoadFile(miIdp3->Caption, -1);
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::miIdp4Click(TObject *Sender)
{
    LoadFile(miIdp4->Caption, -1);
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::miIdp5Click(TObject *Sender)
{
    LoadFile(miIdp5->Caption, -1);
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::miIdp6Click(TObject *Sender)
{
    LoadFile(miIdp6->Caption, -1);
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::miIdp7Click(TObject *Sender)
{
    LoadFile(miIdp7->Caption, -1);
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::miIdp8Click(TObject *Sender)
{
    LoadFile(miIdp8->Caption, -1);
}
//---------------------------------------------------------------------------
//SAVE PROJECT
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::miSaveProjectClick(TObject *Sender)
{
    if (IDPFile == "") IDPFile = ChangeFileExt(SourceFile, ".idp");

    SaveDlg->InitialDir = WrkDir;
    SaveDlg->Filter = "IDP|*.idp";
    SaveDlg->FileName = IDPFile;

    if (SaveDlg->Execute()) SaveProject(SaveDlg->FileName);
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::WriteNode(TStream* stream, TTreeNode* node)
{
    //Count
    int itemsCount = node->Count;
    stream->Write(&itemsCount, sizeof(itemsCount));
    FProgressBar->pb->StepIt();

    //Text
    int len = node->Text.Length(); if (len > MaxBufLen) MaxBufLen = len;
    stream->Write(&len, sizeof(len));
    stream->Write(node->Text.c_str(), len);

    for (int n = 0; n < itemsCount; n++)
    {
        WriteNode(stream, node->Item[n]);
    }
    Application->ProcessMessages();
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::SaveProject(String FileName)
{
    int             n, m, k, len, num, cnum, evnum, size, pos, res, infosCnt, topIdx, itemIdx;
    TMemoryStream*    outStream = 0;
    BYTE            buf[4096];

    if (FileExists(FileName))
    {
        if (Application->MessageBox("File already exists. Overwrite?", "Warning", MB_YESNO | MB_ICONQUESTION) == IDNO) return;
    }

    BusyCursor  cursor;
    
    IDPFile = FileName;

    try
    {
        outStream = new TMemoryStream();

        FProgressBar->Show();

        char* _magic = IDPMAGIC;
        outStream->Write(_magic, IDPMAGICLEN);
        BYTE _idpver = IDPVERSION;
        outStream->Write(&_idpver, sizeof(_idpver));
        int _ver = DelphiVersion;
        if (UserKnowledgeBase) _ver |= USER_KNOWLEDGEBASE;
        if (SourceIsLibrary) _ver |= SOURCE_LIBRARY;
        outStream->Write(&_ver, sizeof(_ver));

        outStream->Write(&EP, sizeof(EP));
        outStream->Write(&ImageBase, sizeof(ImageBase));
        outStream->Write(&ImageSize, sizeof(ImageSize));
        outStream->Write(&TotalSize, sizeof(TotalSize));
        outStream->Write(&CodeBase, sizeof(CodeBase));
        outStream->Write(&CodeSize, sizeof(CodeSize));
        outStream->Write(&CodeStart, sizeof(CodeStart));

        outStream->Write(&DataBase, sizeof(DataBase));
        outStream->Write(&DataSize, sizeof(DataSize));
        outStream->Write(&DataStart, sizeof(DataStart));
        //SegmentList
        num = SegmentList->Count;
        outStream->Write(&num, sizeof(num));
        for (n = 0; n < num; n++)
        {
            PSegmentInfo segInfo = (PSegmentInfo)SegmentList->Items[n];
            outStream->Write(&segInfo->Start, sizeof(segInfo->Start));
            outStream->Write(&segInfo->Size, sizeof(segInfo->Size));
            outStream->Write(&segInfo->Flags, sizeof(segInfo->Flags));
            len = segInfo->Name.Length(); if (len > MaxBufLen) MaxBufLen = len;
            outStream->Write(&len, sizeof(len));
            outStream->Write(segInfo->Name.c_str(), len);
        }

        DWORD Items = TotalSize;
        BYTE *pImage = Image;
        FProgressBar->StartProgress("Writing Image...", "", (Items + MAX_ITEMS - 1)/MAX_ITEMS);
        while (Items >= MAX_ITEMS)
        {
            FProgressBar->pb->StepIt();
            outStream->Write(pImage, MAX_ITEMS);
            pImage += MAX_ITEMS;
            Items -= MAX_ITEMS;
        }
        if (Items) outStream->Write(pImage, Items);

        Items = TotalSize;
        DWORD *pFlags = idr.Flags;
        FProgressBar->StartProgress("Writing Flags...", "", (Items + MAX_ITEMS - 1)/MAX_ITEMS);
        while (Items >= MAX_ITEMS)
        {
            FProgressBar->pb->StepIt();
            outStream->Write(pFlags, sizeof(DWORD)*MAX_ITEMS);
            pFlags += MAX_ITEMS;
            Items -= MAX_ITEMS;
        }
        if (Items) outStream->Write(pFlags, sizeof(DWORD)*Items);

        infosCnt = 0;
        for (n = 0; n < TotalSize; n++)
        {
            PInfoRec recN = GetInfoRec(Pos2Adr(n));
            if (recN) infosCnt++;
        }
        outStream->Write(&infosCnt, sizeof(infosCnt));

        FProgressBar->StartProgress("Writing Infos Objects (number = " + String(infosCnt) + ")...", "", TotalSize / 4096);
        MaxBufLen = 0;
        BYTE kind;
        try
        {
            for (n = 0; n < TotalSize; n++)
            {
                if ((n & 4095) == 0)
                {
                    FProgressBar->pb->StepIt();
                    Application->ProcessMessages();
                }

                PInfoRec recN = GetInfoRec(Pos2Adr(n));
                if (recN)
                {
                    //Position
                    pos = n;
                    outStream->Write(&pos, sizeof(pos));
                    kind = recN->kind;
                    outStream->Write(&kind, sizeof(kind));
                    recN->Save(outStream);
                }
            }
        }
        catch (Exception &exception)
        {
            //ShowMessage("Error at " + Val2Str8(Pos2Adr(n)));
            LogMessage("Error at " + Val2Str8(Pos2Adr(n)), MB_ICONERROR);
        }
        //Last position = -1 -> end of items
        pos = -1; outStream->Write(&pos, sizeof(pos));

        //BSSInfos
        String _adr;
        int bssCnt = idr.GetBSSInfosCount();
        outStream->Write(&bssCnt, sizeof(bssCnt));
        for (n = 0; n < bssCnt; n++)
        {
            _adr = idr.GetBSSInfosString(n);
            len = _adr.Length();  if (len > MaxBufLen) MaxBufLen = len;
            outStream->Write(&len, sizeof(len));
            outStream->Write(_adr.c_str(), len);
            PInfoRec recN = idr.GetBSSInfosObject(n);
            kind = recN->kind;
            outStream->Write(&kind, sizeof(kind));
            recN->Save(outStream);
        }

        //Units
        num = UnitsNum;
        FProgressBar->StartProgress("Writing Units (number = "+String(num)+")...", "", num);
        outStream->Write(&num, sizeof(num));
        for (n = 0; n < num; n++)
        {
            FProgressBar->pb->StepIt();
            Application->ProcessMessages();
            PUnitRec recU = (PUnitRec)Units->Items[n];
            outStream->Write(&recU->trivial, sizeof(recU->trivial));
            outStream->Write(&recU->trivialIni, sizeof(recU->trivialIni));
            outStream->Write(&recU->trivialFin, sizeof(recU->trivialFin));
            outStream->Write(&recU->kb, sizeof(recU->kb));
            outStream->Write(&recU->fromAdr, sizeof(recU->fromAdr));
            outStream->Write(&recU->toAdr, sizeof(recU->toAdr));
            outStream->Write(&recU->finadr, sizeof(recU->finadr));
            outStream->Write(&recU->finSize, sizeof(recU->finSize));
            outStream->Write(&recU->iniadr, sizeof(recU->iniadr));
            outStream->Write(&recU->iniSize, sizeof(recU->iniSize));
            outStream->Write(&recU->iniOrder, sizeof(recU->iniOrder));
            int namesNum = recU->names->Count;
            outStream->Write(&namesNum, sizeof(namesNum));
            for (int u = 0; u < namesNum; u++)
            {
                len = recU->names->Strings[u].Length(); if (len > MaxBufLen) MaxBufLen = len;
                outStream->Write(&len, sizeof(len));
                outStream->Write(recU->names->Strings[u].c_str(), len);
            }
        }
        if (num)
        {
            outStream->Write(&UnitSortField, sizeof(UnitSortField));
            outStream->Write(&CurUnitAdr, sizeof(CurUnitAdr));
            topIdx = lbUnits->TopIndex;
            outStream->Write(&topIdx, sizeof(topIdx));
            itemIdx = lbUnits->ItemIndex;
            outStream->Write(&itemIdx, sizeof(itemIdx));
            //UnitItems
            if (CurUnitAdr)
            {
            	topIdx = lbUnitItems->TopIndex;
            	outStream->Write(&topIdx, sizeof(topIdx));
                itemIdx = lbUnitItems->ItemIndex;
                outStream->Write(&itemIdx, sizeof(itemIdx));
            }
        }

        //Types
        num = OwnTypeList->Count;
        FProgressBar->StartProgress("Writing Types (number = "+String(num)+")...", "", num);
        outStream->Write(&num, sizeof(num));
        for (n = 0; n < num; n++)
        {
            FProgressBar->pb->StepIt();
            Application->ProcessMessages();
            PTypeRec recT = (PTypeRec)OwnTypeList->Items[n];
            outStream->Write(&recT->kind, sizeof(recT->kind));
            outStream->Write(&recT->adr, sizeof(recT->adr));
            len = recT->name.Length(); if (len > MaxBufLen) MaxBufLen = len;
            outStream->Write(&len, sizeof(len));
            outStream->Write(recT->name.c_str(), len);
        }
        if (num) outStream->Write(&RTTISortField, sizeof(RTTISortField));

        //Forms
        num = idr.ResInfo()->GetDfmCount();
        FProgressBar->StartProgress("Writing Forms (number = "+String(num)+")...", "", num);
        outStream->Write(&num, sizeof(num));
        for (n = 0; n < num; n++)
        {
            FProgressBar->pb->StepIt();
            Application->ProcessMessages();
            TDfm* dfm = idr.ResInfo()->GetDfm(n);
            //Flags
            outStream->Write(&dfm->Flags, sizeof(dfm->Flags));
            //ResName
            len = dfm->ResName.Length(); if (len > MaxBufLen) MaxBufLen = len;
            outStream->Write(&len, sizeof(len));
            outStream->Write(dfm->ResName.c_str(), len);
            //Name
            len = dfm->Name.Length(); if (len > MaxBufLen) MaxBufLen = len;
            outStream->Write(&len, sizeof(len));
            outStream->Write(dfm->Name.c_str(), len);
            //ClassName
            len = dfm->ClassName.Length(); if (len > MaxBufLen) MaxBufLen = len;
            outStream->Write(&len, sizeof(len));
            outStream->Write(dfm->ClassName.c_str(), len);
            //MemStream
            size = dfm->MemStream->Size; if (4096 > MaxBufLen) MaxBufLen = 4096;
            outStream->Write(&size, sizeof(size));
            dfm->MemStream->Seek(0, soFromBeginning);
            while (size >= 4096)
            {
                dfm->MemStream->Read(buf, 4096);
                outStream->Write(buf, 4096);
                size -= 4096;
            }
            if (size)
            {
                dfm->MemStream->Read(buf, size);
                outStream->Write(buf, size);
            }
            //Events
            evnum = (dfm->Events) ? dfm->Events->Count : 0;
            outStream->Write(&evnum, sizeof(evnum));
            for (m = 0; m < evnum; m++)
            {
            	PEventInfo eInfo = (PEventInfo)dfm->Events->Items[m];
                //EventName
                len = eInfo->EventName.Length(); if (len > MaxBufLen) MaxBufLen = len;
                outStream->Write(&len, sizeof(len));
                outStream->Write(eInfo->EventName.c_str(), len);
                //ProcName
                len = eInfo->ProcName.Length(); if (len > MaxBufLen) MaxBufLen = len;
                outStream->Write(&len, sizeof(len));
                outStream->Write(eInfo->ProcName.c_str(), len);
            }
            //Components
            cnum = (dfm->Components) ? dfm->Components->Count : 0;
            outStream->Write(&cnum, sizeof(cnum));
            for (m = 0; m < cnum; m++)
            {
                PComponentInfo cInfo = (PComponentInfo)dfm->Components->Items[m];
                //Inherited
                outStream->Write(&cInfo->Inherit, sizeof(cInfo->Inherit));
                //HasGlyph
                outStream->Write(&cInfo->HasGlyph, sizeof(cInfo->HasGlyph));
                //Name
                len = cInfo->Name.Length(); if (len > MaxBufLen) MaxBufLen = len;
                outStream->Write(&len, sizeof(len));
                outStream->Write(cInfo->Name.c_str(), len);
                //ClassName
                len = cInfo->ClassName.Length(); if (len > MaxBufLen) MaxBufLen = len;
                outStream->Write(&len, sizeof(len));
                outStream->Write(cInfo->ClassName.c_str(), len);
                //Events
                evnum = (cInfo->Events) ? cInfo->Events->Count : 0;
                outStream->Write(&evnum, sizeof(evnum));
                for (k = 0; k < evnum; k++)
                {
                    PEventInfo eInfo = (PEventInfo)cInfo->Events->Items[k];
                    //EventName
                    len = eInfo->EventName.Length(); if (len > MaxBufLen) MaxBufLen = len;
                    outStream->Write(&len, sizeof(len));
                    outStream->Write(eInfo->EventName.c_str(), len);
                    //ProcName
                    len = eInfo->ProcName.Length(); if (len > MaxBufLen) MaxBufLen = len;
                    outStream->Write(&len, sizeof(len));
                    outStream->Write(eInfo->ProcName.c_str(), len);
                }
            }
        }
        //Aliases
        num = idr.ResInfo()->GetAliasCount();
        FProgressBar->StartProgress("Writing Aliases  (number = "+String(num)+")...", "", num);
        outStream->Write(&num, sizeof(num));
        for (n = 0; n < num; n++)
        {
            FProgressBar->pb->StepIt();
            Application->ProcessMessages();
            len = idr.ResInfo()->GetAlias(n).Length(); if (len > MaxBufLen) MaxBufLen = len;
            outStream->Write(&len, sizeof(len));
            outStream->Write(idr.ResInfo()->GetAlias(n).c_str(), len);
        }

        //CodeHistory
        outStream->Write(&CodeHistorySize, sizeof(CodeHistorySize));
        outStream->Write(&CodeHistoryPtr, sizeof(CodeHistoryPtr));
        outStream->Write(&CodeHistoryMax, sizeof(CodeHistoryMax));
        PROCHISTORYREC phRec;
        FProgressBar->StartProgress("Writing Code History Items (number = "+String(CodeHistorySize)+")...", "", CodeHistorySize);
        for (n = 0; n < CodeHistorySize; n++)
        {
            FProgressBar->pb->StepIt();
            Application->ProcessMessages();
            outStream->Write(&CodeHistory[n], sizeof(PROCHISTORYREC));
        }

        outStream->Write(&CurProcAdr, sizeof(CurProcAdr));
        topIdx = lbCode->TopIndex;
        outStream->Write(&topIdx, sizeof(topIdx));

        //Important variables
        outStream->Write(&HInstanceVarAdr, sizeof(HInstanceVarAdr));
        outStream->Write(&LastTls, sizeof(LastTls));

        outStream->Write(&Reserved, sizeof(Reserved));
        outStream->Write(&LastResStrNo, sizeof(LastResStrNo));

        outStream->Write(&CtdRegAdr, sizeof(CtdRegAdr));

        //Class Viewer
        //Total nodes (for progress)
        num = 0; if (ClassTreeDone) num = tvClassesFull->Items->Count;
        if (num && Application->MessageBox("Save full Tree of Classes?", "Warning", MB_YESNO | MB_ICONQUESTION) == IDYES)
        {
            outStream->Write(&num, sizeof(num));
            if (num)
            {
                FProgressBar->StartProgress("Writing ClassViewer Tree Nodes (number = "+String(num)+")...", "", num);
                TTreeNode* root = tvClassesFull->Items->GetFirstNode();
                WriteNode(outStream, root);
            }
        }
        else
        {
            num = 0;
            outStream->Write(&num, sizeof(num));
        }
        //At end write MaxBufLen
        outStream->Write(&MaxBufLen, sizeof(MaxBufLen));
        outStream->SaveToFile(IDPFile);
        delete outStream;

        ProjectModified = false;

        AddIdp2MRF(FileName);

        FProgressBar->Hide();
    }
    catch (EFCreateError &E)
    {
        //ShowMessage("Cannot open output file " + IDPFile);
        LogMessage("Cannot open output file " + IDPFile, MB_ICONERROR);
    }
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::AddExe2MRF(String FileName)
{
    int     n, m;
    for (n = 0; n < 8; n++)
    {
        TMenuItem* item = miMRF->Items[n];
        if (SameText(FileName, item->Caption)) break;
    }
    if (n == 8) n--;

    for (m = n; m >= 1; m--)
    {
        miMRF->Items[m]->Caption = miMRF->Items[m - 1]->Caption;
        miMRF->Items[m]->Tag = miMRF->Items[m - 1]->Tag;
        miMRF->Items[m]->Visible = (miMRF->Items[m]->Caption != "");
    }
    miMRF->Items[0]->Caption = FileName;
    miMRF->Items[0]->Tag = DelphiVersion;
    miMRF->Items[0]->Visible = true;
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::AddIdp2MRF(String FileName)
{
    int     n, m;
    for (n = 9; n < 17; n++)
    {
        TMenuItem* item = miMRF->Items[n];
        if (SameText(FileName, item->Caption)) break;
    }
    if (n == 17) n--;

    for (m = n; m >= 10; m--)
    {
        miMRF->Items[m]->Caption = miMRF->Items[m - 1]->Caption;
        miMRF->Items[m]->Visible = (miMRF->Items[m]->Caption != "");
    }
    miMRF->Items[9]->Caption = FileName;
    miMRF->Items[9]->Visible = true;
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::miKBTypeInfoClick(TObject *Sender)
{
    int         idx;
    MProcInfo   pInfo;
    MTypeInfo   tInfo;
    String      typeName, className, propName, sName;

    sName = InputDialogExec("Enter Type Name", "Name:", "");
    if (sName != "")
    {
        //Procedure
        if (KnowledgeBase.GetKBProcInfo(sName, &pInfo, &idx))
        {
            FTypeInfo_11011981->memDescription->Clear();
            FTypeInfo_11011981->memDescription->Lines->Add(KnowledgeBase.GetProcPrototype(&pInfo));
            FTypeInfo_11011981->ShowModal();
            return;
        }
        //Type
        if (KnowledgeBase.GetKBTypeInfo(sName, &tInfo))
        {
            FTypeInfo_11011981->ShowKbInfo(&tInfo);
            return;
        }
        //Property
        className = ExtractClassName(sName);
        propName = ExtractProcName(sName);
        while (1)
        {
            if (KnowledgeBase.GetKBPropertyInfo(className, propName, &tInfo))
            {
                FTypeInfo_11011981->ShowKbInfo(&tInfo);
                return;
            }
            className = GetParentName(className);
            if (className == "") break;
        }
    }
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::FormResize(TObject *Sender)
{
    lbCode->Repaint();
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::EditFunction(DWORD Adr)
{
    BYTE        tag, callKind;
    DWORD       adr, rootAdr;
    int         n, m, a, cnt, size, ofs, offset, dotpos;
    char        *p;
    PUnitRec    recU;
    PInfoRec    recN, recN1;
    PXrefRec 	recX;
    PVmtListRec recV;
    PMethodRec  recM;
    PARGINFO 	argInfo;
    String      line, name, typeDef, item, className, procName;
    char        buf[1024];

	//if (Adr == EP) return;

    recU = GetUnit(Adr);
    if (!recU) return;
    if (Adr == recU->iniadr || Adr == recU->finadr) return;

    recN = GetInfoRec(Adr);
    if (recN)
    {
        FEditFunctionDlg_11011981->Adr = Adr;

        if (FEditFunctionDlg_11011981->ShowModal() == mrOk)
        {
            if (FEditFunctionDlg_11011981->Modified())
                ProjectModified = true;
                
            //local vars
            if (0)//recN->info.procInfo->locals)
            {
                cnt = FEditFunctionDlg_11011981->lbVars->Count;
                recN->procInfo->DeleteLocals();
                for (n = 0; n < cnt; n++)
                {
                    line = FEditFunctionDlg_11011981->lbVars->Items->Strings[n];
                    //'-' - deleted line
                    strcpy(buf, line.c_str());
                    p = strtok(buf, " ");
                    //offset
                    sscanf(p, "%lX", &offset);
                    //size
                    p = strtok(0, " ");
                    sscanf(p, "%lX", &size);
                    //name
                    p = strtok(0, " :");
                    if (stricmp(p, "?"))
                        name = String(p).Trim();
                    else
                        name = "";
                    //type
                    p = strtok(0, " ");
                    if (stricmp(p, "?"))
                        typeDef = String(p).Trim();
                    else
                        typeDef = "";
                    recN->procInfo->AddLocal(-offset, size, name, typeDef);
                }
            }

            idr.ClearFlag(cfPass2, Adr2Pos(Adr));
            idr.AnalyzeProc2(Adr, false, false);
            idr.AnalyzeArguments(Adr);

            //If virtual then propogate VMT names
            //!!! prototype !!!
            procName = ExtractProcName(recN->GetName());
            if (recN->procInfo->flags & PF_VIRTUAL)
            {
                cnt = recN->xrefs->Count;
                for (n = 0; n < cnt; n++)
                {
                    recX = (PXrefRec)recN->xrefs->Items[n];
                    if (recX->type == 'D')
                    {
                        recN1 = GetInfoRec(recX->adr);
                        ofs = GetMethodOfs(recN1, Adr);
                        if (ofs != -1)
                        {
                            //Down (to root)
                            adr = recX->adr; rootAdr = adr;
                            while (adr)
                            {
                                recM = GetMethodInfo(adr, 'V', ofs);
                                if (recM) rootAdr = adr;
                                adr = GetParentAdr(adr);
                            }
                            //Up (all classes that inherits rootAdr)
                            for (m = 0; m < VmtList->Count; m++)
                            {
                                recV = (PVmtListRec)VmtList->Items[m];
                                if (IsInheritsByAdr(recV->vmtAdr, rootAdr))
                                {
                                    recM = GetMethodInfo(recV->vmtAdr, 'V', ofs);
                                    if (recM)
                                    {
                                        className = GetClsName(recV->vmtAdr);
                                        recM->name = className + "." + procName;
                                        if (recM->address != Adr && !recM->abstract)
                                        {
                                            recN1 = GetInfoRec(recM->address);
                                            if (!recN1->HasName())
                                                recN1->SetName(className + "." + procName);
                                            else
                                            {
                                                dotpos = recN1->GetName().Pos(".");
                                                recN1->SetName(recN1->GetName().SubString(1, dotpos) + procName);
                                            }
                                            //recN1->name = className + "." + procName;
                                            recN1->kind = recN->kind;
                                            recN1->type = recN->type;
                                            recN1->procInfo->flags |= PF_VIRTUAL;
                                            recN1->procInfo->DeleteArgs();
                                            recN1->procInfo->AddArg(0x21, 0, 4, "Self", className);
                                            for (a = 1; a < recN->procInfo->args->Count; a++)
                                            {
                                                argInfo = (PARGINFO)recN->procInfo->args->Items[a];
                                                recN1->procInfo->AddArg(argInfo);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            
            //DWORD adr = CurProcAdr;

            //Edit current proc
            if (Adr == CurProcAdr)
            {
                RedrawCode();
                //Current proc from current unit
                if (recU->fromAdr == CurUnitAdr)
                    ShowUnitItems(recU, lbUnitItems->TopIndex, lbUnitItems->ItemIndex);
            }
            else
            {
                ShowUnitItems(recU, lbUnitItems->TopIndex, lbUnitItems->ItemIndex);
            }
            ProjectModified = true;
        }
    }
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::miEditFunctionCClick(TObject *Sender)
{
	EditFunction(CurProcAdr);
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::miMapGeneratorClick(TObject *Sender)
{
    String  procName;

    String  mapName = "";
    if (SourceFile != "") mapName = ChangeFileExt(SourceFile, ".map");
    if (IDPFile != "") mapName = ChangeFileExt(IDPFile, ".map");

    SaveDlg->InitialDir = WrkDir;
    SaveDlg->Filter = "MAP|*.map";
    SaveDlg->FileName = mapName;

    if (!SaveDlg->Execute()) return;

    mapName = SaveDlg->FileName;
    if (FileExists(mapName))
    {
        if (Application->MessageBox("File already exists. Overwrite?", "Warning", MB_YESNO | MB_ICONQUESTION) == IDNO) return;
    }

    BusyCursor  cursor;
    
    FILE *fMap = fopen(mapName.c_str(), "wt+");
    if (!fMap)
    {
        //ShowMessage("Cannot open map file");
        LogMessage("Cannot open map file", MB_ICONWARNING);
        return;
    }
    fprintf(fMap, "\n Start         Length     Name                   Class\n");
    fprintf(fMap, " 0001:00000000 %09XH CODE                   CODE\n", CodeSize);
    fprintf(fMap, "\n\n  Address         Publics by Value\n\n");

    for (int n = 0; n < TotalSize; n++)
    {
        if (idr.IsFlagSet(cfProcStart, n) && !idr.IsFlagSet(cfEmbedded, n))
        {
            int adr = Pos2Adr(n);
            PInfoRec recN = GetInfoRec(adr);
            if (recN)
            {
                if (adr != EP)
                {
                    PUnitRec recU = GetUnit(adr);
                    if (recU)
                    {
                        String moduleName = GetUnitName(recU);
                        if (adr == recU->iniadr)
                            procName = "Initialization";
                        else if (adr == recU->finadr)
                            procName = "Finalization";
                        else
                            procName = recN->MakeMapName(adr);

                        fprintf(fMap, " 0001:%08X       %s.%s\n", n, moduleName.c_str(), procName.c_str());
                    }
                    else
                    {
                        procName = recN->MakeMapName(adr);
                        fprintf(fMap, " 0001:%08X       %s\n", n, procName.c_str());
                    }
                    //if (!idr.IsFlagSet(cfImport, n))
                    //{
                    //    fprintf(fMap, "%lX %s\n", adr, recN->MakePrototype(adr, true, true, false, true, false).c_str());
                    //}
                }
                else
                {
                    fprintf(fMap, " 0001:%08X       EntryPoint\n", n);
                }
            }
        }
    }

    fprintf(fMap, "\nProgram entry point at 0001:%08X\n", EP - CodeBase);
    fclose(fMap);
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::miCommentsGeneratorClick(TObject *Sender)
{
	String		line;

    String txtName = "";
    if (SourceFile != "") txtName = ChangeFileExt(SourceFile, ".txt");
    if (IDPFile != "") txtName = ChangeFileExt(IDPFile, ".txt");
    
    SaveDlg->InitialDir = WrkDir;
    SaveDlg->Filter = "TXT|*.txt";
    SaveDlg->FileName = txtName;

    if (!SaveDlg->Execute()) return;

    txtName = SaveDlg->FileName;

    if (FileExists(txtName))
    {
        if (Application->MessageBox("File already exists. Overwrite?", "Warning", MB_YESNO | MB_ICONQUESTION) == IDNO) return;
    }

    BusyCursor  cursor;

    FILE* lstF = fopen(txtName.c_str(), "wt+");
    /*
    for (int n = 0; n < CodeSize; n++)
    {
        PInfoRec recN = GetInfoRec(Pos2Adr(n));
        if (recN && recN->picode) fprintf(lstF, "C %08lX  %s\n", CodeBase + n, MakeComment(recN->picode).c_str());
    }
    */
    for (int n = 0; n < UnitsNum; n++)
    {
        PUnitRec recU = (PUnitRec)Units->Items[n];
        if (recU->kb || recU->trivial) continue;

        for (DWORD adr = recU->fromAdr; adr < recU->toAdr; adr++)
        {
            if (adr == recU->finadr)
            {
            	if (!recU->trivialFin) OutputCode(lstF, adr, "", true);
                continue;
            }
            if (adr == recU->iniadr)
            {
            	if (!recU->trivialIni) OutputCode(lstF, adr, "", true);
                continue;
            }

            int pos = Adr2Pos(adr);
            PInfoRec recN = GetInfoRec(adr);
            if (!recN) continue;

            BYTE kind = recN->kind;

            if (kind == ikProc        ||
                kind == ikFunc        ||
                kind == ikConstructor ||
                kind == ikDestructor)
            {
               	OutputCode(lstF, adr, "", true);
                continue;
            }

            if (idr.IsFlagSet(cfProcStart, pos))
            {
                if (recN->kind == ikConstructor)
                {
                    OutputCode(lstF, adr, "", true);
                }
                else if (recN->kind == ikDestructor)
                {
                    OutputCode(lstF, adr, "", true);
                }
                else
                    OutputCode(lstF, adr, "", true);
            }
        }
    }
    fclose(lstF);
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::miIDCGeneratorClick(TObject *Sender)
{
    String idcName = "", idcTemplate = "";
    if (SourceFile != "")
    {
        idcName = ChangeFileExt(SourceFile, ".idc");
        idcTemplate = ChangeFileExt(SourceFile, "");
    }
    if (IDPFile != "")
    {
        idcName = ChangeFileExt(IDPFile, ".idc");
        idcTemplate = ChangeFileExt(IDPFile, "");
    }

    TSaveIDCDialog* SaveIDCDialog = new TSaveIDCDialog(this, "SAVEIDCDLG");
    SaveIDCDialog->InitialDir = WrkDir;
    SaveIDCDialog->Filter = "IDC|*.idc";
    SaveIDCDialog->FileName = idcName;
 
    if (!SaveIDCDialog->Execute()) return;

    idcName = SaveIDCDialog->FileName;
    delete SaveIDCDialog;

    TIDCGen *idcGen = new TIDCGen(idcName);

    idcGen->Generate(idcTemplate, CodeBase, TotalSize);

    delete idcGen;
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::pmUnitsPopup(TObject *Sender)
{
    if (lbUnits->ItemIndex < 0) return;

    String item = lbUnits->Items->Strings[lbUnits->ItemIndex];
    DWORD adr;
    sscanf(item.c_str() + 1, "%lX", &adr);
    PUnitRec recU = GetUnit(adr);
    miRenameUnit->Enabled = (!recU->kb && recU->names->Count <= 1);
}
//---------------------------------------------------------------------------
//MXXXXXXXXM   COP Op1, Op2, Op3;commentF
//XXXXXXXX - address
//F - flags (1:cfLoc; 2:cfSkip; 4:cfLoop; 8:jmp or jcc
void __fastcall TFMain_11011981::lbCodeDrawItem(TWinControl *Control,
      int Index, TRect &Rect, TOwnerDrawState State)
{
    bool        ib;
    BYTE        _f, _db;
    int         n, flags, _instrlen, _textLen, _len, _sWid, _cPos, _offset, _ap;
    int         _dbPos, _ddPos;
    DWORD       _adr, _val, _dd;
    TColor      _color;
    TListBox    *lb;
    TCanvas     *canvas;
    String      text, _item, _comment;
    PInfoRec    _recN;
    DISINFO     _disInfo;

    //After closing Project we cannot execute this handler (Code = 0)
    if (!Image) return;

    lb = (TListBox*)Control;
    canvas = lb->Canvas;

    if (Index < lb->Count)
    {
        flags = Control->DrawTextBiDiModeFlags(DT_SINGLELINE | DT_VCENTER | DT_NOPREFIX);
        if (!Control->UseRightToLeftAlignment())
            Rect.Left += 2;
        else
            Rect.Right -= 2;

        text = lb->Items->Strings[Index]; _textLen = text.Length();

        //First row (name of procedure with prototype) output without highlighting
        if (!Index)
        {
            Rect.Right = Rect.Left;
            DrawOneItem(text, canvas, Rect, 0, flags);
            return;
        }
        //F
        _f = text[_textLen];
        canvas->Brush->Color = TColor(0xFFFFFF);
        if (State.Contains(odSelected))
            canvas->Brush->Color = TColor(0xFFFFC0);
        else if (_f & 2)//skip
            canvas->Brush->Color = TColor(0xF5F5FF);
        canvas->FillRect(Rect);

        //Width of space
        _sWid = canvas->TextWidth(" ");
        //Comment position
        _cPos = text.Pos(";");
        //Sign for > (blue)
        _item = text.SubString(1, 1);
        Rect.Right = Rect.Left;
        DrawOneItem(_item, canvas, Rect, TColor(0xFF8080), flags);

        //Address (loop is blue, loc is black, others are light gray)
        _item = text.SubString(2, 8); _adr = StrToInt(String("$") + _item);
        //loop or loc
        if (_f & 5)
            _color = TColor(0xFF8080);
        else
            _color = TColor(0xBBBBBB); 	//LightGray
        DrawOneItem(_item, canvas, Rect, _color, flags);

        //Sign for > (blue)
        _item = text.SubString(10, 1);
        DrawOneItem(_item, canvas, Rect, TColor(0xFF8080), flags);

        //Data (case or exeption table)
        _dbPos = text.Pos(" db ");
        _ddPos = text.Pos(" dd ");
        if (_dbPos || _ddPos)
        {
            Rect.Right += 7 * _sWid;
            if (_dbPos)
            {
                DrawOneItem("db", canvas, Rect, TColor(0), flags);
                //Spaces after db
                Rect.Right += (GetDisasm().GetFormatInstrStops() - 2) * _sWid;
                _db = *(Code + Adr2Pos(_adr));
                DrawOneItem(Val2Str0((DWORD)_db), canvas, Rect, TColor(0xFF8080), flags);
            }
            else if (_ddPos)
            {
                DrawOneItem("dd", canvas, Rect, TColor(0), flags);
                //Spaces after dd
                Rect.Right += (GetDisasm().GetFormatInstrStops() - 2) * _sWid;
                _dd = *((DWORD*)(Code + Adr2Pos(_adr)));
                DrawOneItem(Val2Str8(_dd), canvas, Rect, TColor(0xFF8080), flags);
            }
            //Comment (light gray)
            if (_cPos)
            {
                _item = text.SubString(_cPos, _textLen);
                _item.SetLength(_item.Length() - 1);
                DrawOneItem(_item, canvas, Rect, TColor(0xBBBBBB), flags);
            }
            return;
        }
        //Get instruction tokens
        GetDisasm().Disassemble(Code + Adr2Pos(_adr), (__int64)_adr, &_disInfo, 0);
        //repprefix
        _len = 0;
        if (_disInfo.RepPrefix != -1)
        {
            _item = GetDisasm().GetRepPrefixes(_disInfo.RepPrefix);
            _len = _item.Length();
        }
        Rect.Right += (6 - _len) * _sWid;
        if (_disInfo.RepPrefix != -1)
        {
            DrawOneItem(_item, canvas, Rect, TColor(0), flags);
        }
        Rect.Right += _sWid;

        //Cop (black, if float then green)
        _item = GetDisasm().GetMnemonic(_disInfo.MnemIdx); _len = _item.Length();
        if (!_disInfo.Float)
            _color = TColor(0);
        else
            _color = TColor(0x808000);
        if (!SameText(_item, "movs"))
        {
            DrawOneItem(_item, canvas, Rect, _color, flags);
            //Operands
            if (_disInfo.OpNum)
            {
                Rect.Right += (GetDisasm().GetFormatInstrStops() - _len) * _sWid;
                for (n = 0; n < _disInfo.OpNum; n++)
                {
                    if (n) DrawOneItem(",", canvas, Rect, TColor(0), flags);
                
                    ib = (_disInfo.BaseReg != -1 || _disInfo.IndxReg != -1);
                    _offset = _disInfo.Offset;
                    //Op1
                    if (_disInfo.OpType[n] == otIMM)
                    {
                        _val = _disInfo.Immediate;
                        _ap = Adr2Pos(_val);
                        _color = TColor(0xFF8080);
                        if (_ap >= 0 && (_disInfo.Call || _disInfo.Branch))
                        {
                            _recN = GetInfoRec(_val);
                            if (_recN && _recN->HasName())
                            {
                                _item = _recN->GetName();
                                _color = TColor(0xC08000);
                            }
                            else
                                _item = Val2Str8(_val);
                        }
                        else
                        {
                            if (_val <= 9)
                                _item = String(_val);
                            else
                            {
                                _item = Val2Str0(_val);
                                if (!isdigit(_item[1])) _item = "0" + _item;
                            }
                        }
                        DrawOneItem(_item, canvas, Rect, _color, flags);
                    }
                    else if (_disInfo.OpType[n] == otREG || _disInfo.OpType[n] == otFST)
                    {
                        _item = GetDisasm().GetAsmRegisterName(_disInfo.OpRegIdx[n]);
                        DrawOneItem(_item, canvas, Rect, TColor(0x0000B0), flags);
                    }
                    else if (_disInfo.OpType[n] == otMEM)
                    {
                        if (_disInfo.OpSize)
                        {
                            _item = GetDisasm().GetOpSizeName(_disInfo.OpSize) + " ptr ";
                            DrawOneItem(_item, canvas, Rect, TColor(0), flags);
                        }
                        if (_disInfo.SegPrefix != -1)
                        {
                            _item = String(GetDisasm().GetrgszSReg(_disInfo.SegPrefix));
                            DrawOneItem(_item, canvas, Rect, TColor(0x0000B0), flags);
                            DrawOneItem(":", canvas, Rect, TColor(0), flags);
                        }
                        DrawOneItem("[", canvas, Rect, TColor(0), flags);
                        if (ib)
                        {
                            if (_disInfo.BaseReg != -1)
                            {
                                _item = GetDisasm().GetAsmRegisterName(_disInfo.BaseReg);
                                DrawOneItem(_item, canvas, Rect, TColor(0x0000B0), flags);
                            }
                            if (_disInfo.IndxReg != -1)
                            {
                                if (_disInfo.BaseReg != -1)
                                {
                                    DrawOneItem("+", canvas, Rect, TColor(0), flags);
                                }
                                _item = GetDisasm().GetAsmRegisterName(_disInfo.IndxReg);
                                DrawOneItem(_item, canvas, Rect, TColor(0x0000B0), flags);
                                if (_disInfo.Scale != 1)
                                {
                                    DrawOneItem("*", canvas, Rect, TColor(0), flags);
                                    _item = String(_disInfo.Scale);
                                    DrawOneItem(_item, canvas, Rect, TColor(0xFF8080), flags);
                                }
                            }
                            if (_offset)
                            {
                                if (_offset < 0)
                                {
                                    _item = "-";
                                    _offset = -_offset;
                                }
                                else
                                {
                                    _item = "+";
                                }
                                DrawOneItem(_item, canvas, Rect, TColor(0), flags);
                                if (_offset < 9)
                                    _item = String(_offset);
                                else
                                {
                                    _item = Val2Str0(_offset);
                                    if (!isdigit(_item[1])) _item = "0" + _item;
                                }
                                DrawOneItem(_item, canvas, Rect, TColor(0xFF8080), flags);
                            }
                        }
                        else
                        {
                            if (_offset < 0) _offset = -_offset;
                            if (_offset < 9)
                                _item = String(_offset);
                            else
                            {
                                _item = Val2Str0(_offset);
                                if (!isdigit(_item[1])) _item = "0" + _item;
                            }
                            DrawOneItem(_item, canvas, Rect, TColor(0xFF8080), flags);
                        }
                        DrawOneItem("]", canvas, Rect, TColor(0), flags);
                    }
                }
            }
        }
        //movsX
        else
        {
            _item += String(_disInfo.sSize[0]);
            DrawOneItem(_item, canvas, Rect, _color, flags);
        }
        //Comment (light gray)
        if (_cPos)
        {
            _item = text.SubString(_cPos, _textLen);
            _item.SetLength(_item.Length() - 1);
            DrawOneItem(_item, canvas, Rect, TColor(0xBBBBBB), flags);
        }
    }
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::miListerClick(TObject *Sender)
{
    bool        imp, emb;
	String		line;

    String lstName = "";
    if (SourceFile != "") lstName = ChangeFileExt(SourceFile, ".lst");
    if (IDPFile != "") lstName = ChangeFileExt(IDPFile, ".lst");

    SaveDlg->InitialDir = WrkDir;
    SaveDlg->Filter = "LST|*.lst";
    SaveDlg->FileName = lstName;

    if (!SaveDlg->Execute()) return;

    lstName = SaveDlg->FileName;

    if (FileExists(lstName))
    {
        if (Application->MessageBox("File already exists. Overwrite?", "Warning", MB_YESNO | MB_ICONQUESTION) == IDNO) return;
    }

    BusyCursor  cursor;

    FILE* lstF = fopen(lstName.c_str(), "wt+");
    for (int n = 0; n < UnitsNum; n++)
    {
        PUnitRec recU = (PUnitRec)Units->Items[n];
        if (recU->kb || recU->trivial) continue;
        fprintf(lstF, "//===========================================================================\n");
        fprintf(lstF, "//Unit%03d", recU->iniOrder);
        if (recU->names->Count) fprintf(lstF, " (%s)", recU->names->Strings[0]);
        fprintf(lstF, "\n");

        for (DWORD adr = recU->fromAdr; adr < recU->toAdr; adr++)
        {
            if (adr == recU->finadr)
            {
            	if (!recU->trivialFin)
                {
                    OutputCode(lstF, adr, "procedure Finalization;", false);
                }
                continue;
            }
            if (adr == recU->iniadr)
            {
            	if (!recU->trivialIni)
                {
                    OutputCode(lstF, adr, "procedure Initialization;", false);
                }
                continue;
            }

            int pos = Adr2Pos(adr);
            PInfoRec recN = GetInfoRec(adr);
            if (!recN) continue;

            imp = emb = false;
            BYTE kind = recN->kind;
            if (idr.IsFlagSet(cfProcStart, pos))
            {
                imp = idr.IsFlagSet(cfImport, pos);
                emb = (recN->procInfo->flags & PF_EMBED);
            }

            if (kind == ikUnknown) continue;

            if (kind > ikUnknown && kind <= ikProcedure && recN->HasName())
            {
            	if (kind == ikEnumeration || kind == ikSet)
                {
                	line = FTypeInfo_11011981->GetRTTI(adr);
                    fprintf(lstF, "%s = %s;\n", recN->GetName(), line);
                }
                else
                	fprintf(lstF, "%08lX <%s> %s\n", adr, TypeKind2Name(kind), recN->GetName());
                continue;
            }

            if (kind == ikResString)
            {
                fprintf(lstF, "%08lX <ResString> %s=%s\n", adr, recN->GetName(), recN->rsInfo->value);
                continue;
            }

            if (kind == ikVMT)
            {
            	fprintf(lstF, "%08lX <VMT> %s\n", adr, recN->GetName());
                continue;
            }

            if (kind == ikGUID)
            {
                fprintf(lstF, "%08lX <TGUID> %s\n", adr, Guid2String(Code + pos));
                continue;
            }

            if (kind == ikConstructor)
            {
               	OutputCode(lstF, adr, recN->MakePrototype(adr, true, false, false, true, false), false);
                continue;
            }

            if (kind == ikDestructor)
            {
                OutputCode(lstF, adr, recN->MakePrototype(adr, true, false, false, true, false), false);
                continue;
            }

            if (kind == ikProc)
            {
            	line = "";
                if (imp)
                	line += "import ";
                else if (emb)
                	line += "embedded ";
                line += recN->MakePrototype(adr, true, false, false, true, false);
                OutputCode(lstF, adr, line, false);
                continue;
            }

            if (kind == ikFunc)
            {
            	line = "";
                if (imp)
                	line += "import ";
                else if (emb)
                	line += "embedded ";
                line += recN->MakePrototype(adr, true, false, false, true, false);
                OutputCode(lstF, adr, line, false);
                continue;
            }

            if (idr.IsFlagSet(cfProcStart, pos))
            {
                if (kind == ikDestructor)
                {
                    OutputCode(lstF, adr, recN->MakePrototype(adr, true, false, false, true, false), false);
                }
                else if (kind == ikDestructor)
                {
                    OutputCode(lstF, adr, recN->MakePrototype(adr, true, false, false, true, false), false);
                }
                else
                {
                    line = "";
                    if (emb) line += "embedded ";
                    line += recN->MakePrototype(adr, true, false, false, true, false);
                    OutputCode(lstF, adr, line, false);
                }
            }
        }
    }
    fclose(lstF);
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::OutputLine(FILE* OutF, BYTE flags, DWORD Adr, String Content)
{
    //Ouput comments
    if (flags & 0x10)
    {
        char *p = strchr(Content.c_str(), ';');
        if (p) fprintf(OutF, "C %08lX %s\n", Adr, p + 1);
        return;
    }
    
    //Jump direction
	if (flags & 4)
    	fprintf(OutF, "<");
    else if (flags & 8)
    	fprintf(OutF, ">");
    else
        fprintf(OutF, " ");
    /*
	if (flags & 1)
    	fprintf(OutF, "%08lX\n", Adr);
    else
    	fprintf(OutF, "        ");
    */
    fprintf(OutF, "%08lX    %s\n", Adr, Content.c_str());
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::OutputCode(FILE* outF, DWORD fromAdr, String prototype, bool onlyComments)
{
    BYTE        op, flags;
    int			row = 0, num, instrLen, instrLen1, instrLen2;
    DWORD       Adr, Adr1, Pos, lastMovAdr = 0;
    int         fromPos, curPos, _procSize, _ap, _pos, _idx;
    DWORD       curAdr;
    DWORD       lastAdr = 0;
    PInfoRec    recN, recN1;
    String		line;
    DISINFO     DisInfo, DisInfo1;
    char        disLine[1024];

    fromPos = Adr2Pos(fromAdr);
    if (fromPos < 0) return;

    recN = GetInfoRec(fromAdr);
    int outRows = MAX_DISASSEMBLE;
    if (idr.IsFlagSet(cfImport, fromPos)) outRows = 1;

    if (!onlyComments && prototype != "")
    {
        fprintf(outF, "//---------------------------------------------------------------------------\n");
        fprintf(outF, "//%s\n", prototype);
    }
    _procSize = GetProcSize(fromAdr);
    curPos = fromPos; curAdr = fromAdr;

    while (row < outRows)
    {
        //End of procedure
        if (curAdr != fromAdr && _procSize && curAdr - fromAdr >= _procSize) break;
        flags = 0;
        //Only comments?
        if (onlyComments) flags |= 0x10;
        //Loc?
        if (idr.IsFlagSet(cfLoc, curPos)) flags |= 1;
        //Skip?
        if (idr.IsFlagSet(cfSkip | cfDSkip, curPos)) flags |= 2;

        BYTE b1 = Code[curPos];
        BYTE b2 = Code[curPos + 1];
        if (!b1 && !b2 && !lastAdr) break;

        instrLen = GetDisasm().Disassemble(Code + curPos, (__int64)curAdr, &DisInfo, disLine);
        if (!instrLen)
        {
            OutputLine(outF, flags, curAdr, "???"); row++;
            curPos++; curAdr++;
            continue;
        }
        op = GetDisasm().GetOp(DisInfo.MnemIdx);

        //Check inside instruction Fixup or ThreadVar
        bool NameInside = false; DWORD NameInsideAdr;
        for (int k = 1; k < instrLen; k++)
        {
            if (idr.HasInfosAt(curPos + k))
            {
                NameInside = true;
                NameInsideAdr= curAdr + k;
                break;
            }
        }

        line = String(disLine);

        if (curAdr >= lastAdr) lastAdr = 0;

        //Proc end
        if (DisInfo.Ret && (!lastAdr || curAdr == lastAdr))
        {
            OutputLine(outF, flags, curAdr, line); row++;
            break;
        }

        if (op == OP_MOV) lastMovAdr = DisInfo.Offset;

        if (b1 == 0xEB ||				 //short relative abs jmp or cond jmp
        	(b1 >= 0x70 && b1 <= 0x7F) ||
            (b1 == 0xF && b2 >= 0x80 && b2 <= 0x8F))
        {
            Adr = DisInfo.Immediate;
            if (IsValidCodeAdr(Adr))
            {
                if (op == OP_JMP)
                {
                    _ap = Adr2Pos(Adr);
                    recN = GetInfoRec(Adr);
                    if (recN && idr.IsFlagSet(cfProcStart, _ap) && recN->HasName())
                    {
                        line = "jmp         " + recN->GetName();
                    }
                }
                flags |= 8;
                if (Adr >= fromAdr && Adr > lastAdr) lastAdr = Adr;
            }
            OutputLine(outF, flags, curAdr, line); row++;
            curPos += instrLen; curAdr += instrLen;
            continue;
        }

        if (b1 == 0xE9)    //relative abs jmp or cond jmp
        {
            Adr = DisInfo.Immediate;
            if (IsValidCodeAdr(Adr))
            {
                _ap = Adr2Pos(Adr);
                recN = GetInfoRec(Adr);
                if (recN && idr.IsFlagSet(cfProcStart, _ap) && recN->HasName())
                {
                    line = "jmp         " + recN->GetName();
                }
                flags |= 8;
                if (!recN && Adr >= fromAdr && Adr > lastAdr) lastAdr = Adr;
            }
            OutputLine(outF, flags, curAdr, line); row++;
            curPos += instrLen; curAdr += instrLen;
            continue;
        }
        
        if (DisInfo.Call)  //call sub_XXXXXXXX
        {
            Adr = DisInfo.Immediate;
            if (IsValidCodeAdr(Adr))
            {
                recN = GetInfoRec(Adr);
                if (recN && recN->HasName())
                {
                    line = "call        " + recN->GetName();
                    //Found @Halt0 - exit
                    if (recN->SameName("@Halt0") && fromAdr == EP && !lastAdr)
                    {
                        OutputLine(outF, flags, curAdr, line); row++;
                        break;
                    }
                }
            }
            recN = GetInfoRec(curAdr);
            if (recN && recN->picode) line += ";" + MakeComment(recN->picode);
            OutputLine(outF, flags, curAdr, line); row++;
            curPos += instrLen; curAdr += instrLen;
            continue;
        }
        //Name inside instruction (Fixip, ThreadVar)
        String namei = "", comment = "", name, pname, type, ptype;
        if (NameInside)
        {
            recN = GetInfoRec(NameInsideAdr);
            if (recN && recN->HasName())
            {
                namei += recN->GetName();
                if (recN->type != "") namei +=  ":" + recN->type;
            }
        }
        //comment
        recN = GetInfoRec(curAdr);
        if (recN && recN->picode) comment = MakeComment(recN->picode);

        DWORD targetAdr = 0;
        if (IsValidImageAdr(DisInfo.Immediate))
        {
        	if (!IsValidImageAdr(DisInfo.Offset)) targetAdr = DisInfo.Immediate;
        }
        else if (IsValidImageAdr(DisInfo.Offset))
        	targetAdr = DisInfo.Offset;

        if (targetAdr)
        {
            name = pname = type = ptype = "";
            _pos = Adr2Pos(targetAdr);
            if (_pos >= 0)
            {
                recN = GetInfoRec(targetAdr);
                if (recN)
                {
                    if (recN->kind == ikResString)
                    {
                        name = recN->GetName() + ":PResStringRec";
                    }
                    else
                    {
                        if (recN->HasName())
                        {
                            name = recN->GetName();
                            if (recN->type != "") type = recN->type;
                        }
                        else if (idr.IsFlagSet(cfProcStart, _pos))
                            name = GetDefaultProcName(targetAdr);
                    }
                }
                Adr = *((DWORD*)(Code + _pos));
                if (IsValidImageAdr(Adr))
                {
                    recN = GetInfoRec(Adr);
                    if (recN)
                    {
                        if (recN->HasName())
                        {
                            pname = recN->GetName();
                            ptype = recN->type;
                        }
                        else if (idr.IsFlagSet(cfProcStart, _pos))
                            pname = GetDefaultProcName(Adr);
                    }
                }
            }
            else
            {
                recN = idr.GetBSSInfosRec(Val2Str8(targetAdr));
                if (recN)
                {
                    name = recN->GetName();
                    type = recN->type;
                }
            }
        }
        if (SameText(comment, name)) name = "";
        if (pname != "")
        {
            if (comment != "") comment += " ";
            comment += "^" + pname;
            if (ptype != "") comment += ":" + ptype;
        }
        else if (name != "")
        {
            if (comment != "") comment += " ";
           	comment += name;
            if (type != "") comment += ":" + type;
        }

        if (comment != "" || namei != "")
        {
            line += ";";
            if (comment != "") line += comment;
            if (namei != "") line += "{" + namei + "}";
        }
        if (line.Length() > MAXLEN) line = line.SubString(1, MAXLEN) + "...";
        OutputLine(outF, flags, curAdr, line); row++;
        curPos += instrLen; curAdr += instrLen;
    }
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::wm_dropFiles(TWMDropFiles& msg)
{
    TFileDropper* fc = new TFileDropper((HDROP)msg.Drop);
    try
    {
        for (int i = 0; i < fc->FileCount; ++i)
        {
            String droppedFile = fc->Files[i];
            String ext = ExtractFileExt(droppedFile).LowerCase();

            if (SameText(ext, ".lnk"))
            	DoOpenDelphiFile(DELHPI_VERSION_AUTO, GetFilenameFromLink(droppedFile), true, true);
            else if (SameText(ext, ".idp") && miOpenProject->Enabled)
                DoOpenProjectFile(droppedFile);
            else if ((SameText(ext, ".exe") || SameText(ext, ".bpl") || SameText(ext, ".dll") || SameText(ext, ".scr")) && miLoadFile->Enabled)
                DoOpenDelphiFile(DELHPI_VERSION_AUTO, droppedFile, true, true);

            //Processed the first - and go out - we cannot process more than one file yet
            break;
        }
        //TPoint ptDrop = fc->DropPoint;
    }
    catch (...)
    {
    }
    delete fc;
    msg.Result = 0;
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::miAboutClick(TObject *Sender)
{
	FAboutDlg_11011981->ShowModal();
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::miHelpClick(TObject *Sender)
{
	ShellExecute(Handle, "open", Application->HelpFile.c_str(), 0, 0, 1);
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::FormCloseQuery(TObject *Sender, bool &CanClose)
{
    int _res;

    if (AnalyzeThread)
    {
        AnalyzeThread->Suspend();
        String sbtext0 = FProgressBar->sb->Panels->Items[0]->Text;
        String sbtext1 = FProgressBar->sb->Panels->Items[1]->Text;
        FProgressBar->Hide();

        _res = Application->MessageBox("Analysis is not yet completed. Do You really want to exit IDR?", "Confirmation", MB_YESNO | MB_ICONQUESTION);
    	if (_res == IDNO)
        {
            FProgressBar->Show();
            FProgressBar->sb->Panels->Items[0]->Text = sbtext0;
            FProgressBar->sb->Panels->Items[1]->Text = sbtext1;
            FProgressBar->Update();

            AnalyzeThread->Resume();
        	CanClose = false;
            return;
        }
        AnalyzeThread->Terminate();
    }

    if (ProjectLoaded && ProjectModified)
    {
        _res = Application->MessageBox("Save active Project?", "Confirmation", MB_YESNOCANCEL | MB_ICONQUESTION);
        if (_res == IDCANCEL)
        {
          	CanClose = false;
            return;
        }
    	if (_res == IDYES)
        {
            if (IDPFile == "") IDPFile = ChangeFileExt(SourceFile, ".idp");

            SaveDlg->InitialDir = WrkDir;
            SaveDlg->Filter = "IDP|*.idp";
            SaveDlg->FileName = IDPFile;

            if (!SaveDlg->Execute())
            {
            	CanClose = false;
                return;
            }
            SaveProject(SaveDlg->FileName);
        }
        CloseProject();
    }

    IniFileWrite();
    
    CanClose = true;
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::miCtdPasswordClick(TObject *Sender)
{
    BYTE        op;
    DWORD       curPos, curAdr;
    int         instrLen, pwdlen = 0, beg;
    String      pwds = "";
    BYTE        pwd[256];
    DISINFO     DisInfo;

	PInfoRec recN = GetInfoRec(CtdRegAdr);
    if (recN->xrefs->Count != 1) return;
    PXrefRec recX = (PXrefRec)recN->xrefs->Items[0];

    int ofs;
    for (ofs = recX->offset; ofs >= 0; ofs--)
    {
        if (idr.IsFlagSet(cfPush, Adr2Pos(recX->adr) + ofs)) break;
    }
    /*    
    curPos = Adr2Pos(recX->adr) + ofs;
    curAdr = Pos2Adr(curPos);
    //pwdlen
    instrLen = Disasm.Disassemble(Code + curPos, (__int64)curAdr, &DisInfo);
    pwdlen = DisInfo.Immediate + 1;
    curPos += instrLen; curAdr += instrLen;
    //pwd
    beg = 128;
    for (int n = 0; n < pwdlen;)
    {
        instrLen = Disasm.Disassemble(Code + curPos, (__int64)curAdr, &DisInfo);
        op = Disasm.GetOp(DisInfo.Mnem);
        //mov [ebp-Ofs], B
        if (op == OP_MOV && DisInfo.Op1Type == otMEM && DisInfo.Op2Type == otIMM && DisInfo.BaseReg == 21 && (int)DisInfo.Offset < 0)
        {
            ofs = DisInfo.Offset; if (128 + ofs < beg) beg = 128 + ofs;
            pwd[128 + ofs] = DisInfo.Immediate;
            n++;
        }
        curPos += instrLen; curAdr += instrLen;
    }
    for (int n = beg; n < beg + pwdlen; n++)
    {
        pwds += Val2Str2(pwd[n]);
    }
    */
	PROCHISTORYREC  rec;

    rec.adr = CurProcAdr;
    rec.itemIdx = lbCode->ItemIndex;
    rec.xrefIdx = lbCXrefs->ItemIndex;
    rec.topIdx = lbCode->TopIndex;
    ShowCode(recX->adr, recX->adr + ofs, -1, -1);
    CodeHistoryPush(&rec);
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::pmCodePanelPopup(TObject *Sender)
{
    miEmptyHistory->Enabled = (CodeHistoryPtr > 0);
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::miEmptyHistoryClick(TObject *Sender)
{
    memmove(&CodeHistory[0], &CodeHistory[CodeHistoryPtr], sizeof(PROCHISTORYREC));
    CodeHistoryPtr = 0;
    CodeHistoryMax = CodeHistoryPtr;
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::miUnitDumperClick(TObject *Sender)
{
;
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::miFuzzyScanKBClick(TObject *Sender)
{
    FKBViewer_11011981->Position = -1;
    if (CurProcAdr)
    {
        PInfoRec recN = GetInfoRec(CurProcAdr);
        if (recN && recN->kbIdx != -1)
        {
            FKBViewer_11011981->Position = recN->kbIdx;
            FKBViewer_11011981->ShowCode(CurProcAdr, recN->kbIdx, lbCode);
            FKBViewer_11011981->Show();
            return;
        }

        PUnitRec recU = GetUnit(CurProcAdr);
        if (recU)
        {
            int fromAdr = recU->fromAdr, toAdr = recU->toAdr;
            int upIdx = -1, dnIdx = -1, upCnt = -1, dnCnt = -1;
            if (1)//!recU->names->Count)
            {
                if (FKBViewer_11011981->cbUnits->Text != "")
                {
                    FKBViewer_11011981->cbUnitsChange(this);
                }
                else if (recU->names->Count)
                {
                    FKBViewer_11011981->cbUnits->Text = recU->names->Strings[0];
                    FKBViewer_11011981->cbUnitsChange(this);
                }
                if (FKBViewer_11011981->Position != -1)
                {
                    FKBViewer_11011981->Show();
                }
                else
                {
                    for (int adr = CurProcAdr; adr >= fromAdr; adr--)
                    {
                        if (idr.IsFlagSet(cfProcStart, Adr2Pos(adr)))
                        {
                            upCnt++;
                            recN = GetInfoRec(adr);
                            if (recN && recN->kbIdx != -1)
                            {
                                upIdx = recN->kbIdx;
                                break;
                            }
                        }
                    }
                    for (int adr = CurProcAdr; adr < toAdr; adr++)
                    {
                        if (idr.IsFlagSet(cfProcStart, Adr2Pos(adr)))
                        {
                            dnCnt++;
                            recN = GetInfoRec(adr);
                            if (recN && recN->kbIdx != -1)
                            {
                                dnIdx = recN->kbIdx;
                                break;
                            }
                        }
                    }
                    if (upIdx != -1)
                    {
                        if (dnIdx != -1)
                        {
                            //Up proc is nearest
                            if (upCnt < dnCnt)
                            {
                                FKBViewer_11011981->Position = upIdx + upCnt;
                                FKBViewer_11011981->ShowCode(CurProcAdr, upIdx + upCnt, lbCode);
                                FKBViewer_11011981->Show();
                            }
                            //Down is nearest
                            else
                            {
                                FKBViewer_11011981->Position = dnIdx - dnCnt;
                                FKBViewer_11011981->ShowCode(CurProcAdr, dnIdx - dnCnt, lbCode);
                                FKBViewer_11011981->Show();
                            }
                        }
                        else
                        {
                            FKBViewer_11011981->Position = upIdx + upCnt;
                            FKBViewer_11011981->ShowCode(CurProcAdr, upIdx + upCnt, lbCode);
                            FKBViewer_11011981->Show();
                        }
                    }
                    else if (dnIdx != -1)
                    {
                        FKBViewer_11011981->Position = dnIdx - dnCnt;
                        FKBViewer_11011981->ShowCode(CurProcAdr, dnIdx - dnCnt, lbCode);
                        FKBViewer_11011981->Show();
                    }
                    //Nothing found!
                    else
                    {
                        FKBViewer_11011981->Position = -1;
                        FKBViewer_11011981->ShowCode(CurProcAdr, -1, lbCode);
                        FKBViewer_11011981->Show();
                    }
                }
                return;
            }
        }
    }
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::InitAliases(bool find)
{
    BusyCursor  cursor;

    if (find) idr.ResInfo()->InitAliases();

    lClassName->Caption = "";
    lbAliases->Clear();

    for (int n = 0; n < idr.ResInfo()->GetAliasCount(); n++)
    {
        String item = idr.ResInfo()->GetAlias(n);
        if (item.Pos("="))
        {
            char *p = AnsiLastChar(item);
            if (p && *p != '=') lbAliases->Items->Add(item);
        }
    }

    cbAliases->Clear();

    for (int n = 0;; n++)
    {
        if (!RegClasses[n].RegClass) break;

        if (RegClasses[n].ClassName)
            cbAliases->Items->Add(String(RegClasses[n].ClassName));
    }

    pnlAliases->Visible = false;
    lbAliases->Enabled = true;
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::lbAliasesDblClick(TObject *Sender)
{
    lClassName->Caption = "";
    cbAliases->Text = "";
    String item = lbAliases->Items->Strings[lbAliases->ItemIndex];
    int pos = item.Pos("=");
    if (pos)
    {
        pnlAliases->Visible = true;
        lClassName->Caption = item.SubString(1, pos - 1);
        cbAliases->Text = item.SubString(pos + 1, item.Length() - pos);
        lbAliases->Enabled = false;
    }
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::bApplyAliasClick(TObject *Sender)
{
    idr.ResInfo()->SetAliasValue(lClassName->Caption, cbAliases->Text);
    pnlAliases->Visible = false;
    lbAliases->Items->Strings[lbAliases->ItemIndex] = lClassName->Caption + "=" + cbAliases->Text;
    lbAliases->Enabled = true;

    //as: we any opened Forms -> repaint (take into account new aliases)
    idr.ResInfo()->ReopenAllForms();    
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::bCancelAliasClick(TObject *Sender)
{
    pnlAliases->Visible = false;
    lbAliases->Enabled = true;
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::miLegendClick(TObject *Sender)
{
    FLegend_11011981->ShowModal();
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::miCopyListClick(TObject *Sender)
{
    int         n, m, k, u, dot, idx, usesNum;
    PInfoRec    recN;
    PUnitRec    recU;
    MProcInfo   aInfo;
    MProcInfo   *pInfo = &aInfo;
    FILE        *outFile;
    TStringList *tmpList;
    String      moduleName, importName;
    WORD        uses[128];

    SaveDlg->InitialDir = WrkDir;
    SaveDlg->FileName = "units.lst";

    if (SaveDlg->Execute())
    {
        if (FileExists(SaveDlg->FileName))
        {
            if (Application->MessageBox("File already exists. Overwrite?", "Warning", MB_YESNO | MB_ICONQUESTION) == IDNO) return;
        }
        
        outFile = fopen(SaveDlg->FileName.c_str(), "wt+");
        if (!outFile)
        {
            //ShowMessage("Cannot save units list");
            LogMessage("Cannot save units list", MB_ICONWARNING);
            return;
        }

        BusyCursor  cursor;

        tmpList = new TStringList;
        for (n = 0; n < UnitsNum; n++)
        {
            recU = (UnitRec*)Units->Items[n];
            for (u = 0; u < recU->names->Count; u++)
            {
                if (tmpList->IndexOf(recU->names->Strings[u]) == -1) tmpList->Add(recU->names->Strings[u]);
            }
            //Add Imports
            for (m = 0; m < TotalSize; m += 8)
            {
                if (idr.IsFlagSet(cfImport, m))
                {
                    recN = GetInfoRec(Pos2Adr(m));
                    dot = recN->GetName().Pos(".");
                    importName = recN->GetName().SubString(dot + 1, recN->GetNameLength());
                    usesNum = KnowledgeBase.GetProcUses(importName.c_str(), uses);
                    for (k = 0; k < usesNum; k++)
                    {
                        idx = KnowledgeBase.GetProcIdx(uses[k], importName.c_str());
                        if (idx != -1)
                        {
                            idx = KnowledgeBase.ProcOffsets[idx].NamId;
                            if (KnowledgeBase.GetProcInfo(idx, INFO_ARGS, pInfo))
                            {
                                moduleName = KnowledgeBase.GetModuleName(pInfo->ModuleID);
                                if (tmpList->IndexOf(moduleName) == -1) tmpList->Add(moduleName);
                            }
                        }
                    }
                }
            }
            tmpList->Sort();
        }
        //Output result
        for (n = 0; n < tmpList->Count; n++)
        {
            fprintf(outFile, "%s.dcu\n", tmpList->Strings[n].c_str());
        }
        delete tmpList;
        fclose(outFile);
    }
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::wm_showClassViewer(TMessage& msg)
{
    ShowClassViewer(msg.LParam);
}
//---------------------------------------------------------------------------
//Note: if LParam is 0 - just redraw the code
//
void __fastcall TFMain_11011981::wm_showCode(TMessage& msg)
{
    //2 means "add new line of code into code list box
    if (2 == msg.WParam)
    {
        lbSourceCode->Items->Add(String(StringBuf)); //this is bad dependency!
        return;
    }
    else if (3 == msg.WParam)
    {
        RedrawCode();

        if (1 == msg.LParam)
        {
            ShowUnitItems(GetUnit(CurUnitAdr), lbUnitItems->TopIndex, lbUnitItems->ItemIndex);
        }
        return;
    }

    const ShowCodeData* codeData = (ShowCodeData*)msg.LParam;
    if (codeData)
    {
        ShowCode(codeData->adr, codeData->idxCode, codeData->idxXRef, codeData->idxTopCode);
        delete codeData;
    }
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::wm_updAnalysisStatus(TMessage& msg)
{
    if (taUpdateUnits == msg.WParam)
    {
        const long isLastStep = msg.LParam;
        tsUnits->Enabled = true;
        ShowUnits(isLastStep);
        ShowUnitItems(GetUnit(CurUnitAdr), lbUnitItems->TopIndex, lbUnitItems->ItemIndex);
    }
    else if (taUpdateRTTIs == msg.WParam)
    {
        miSearchRTTI->Enabled = true;
        miSortRTTI->Enabled = true;
        tsRTTIs->Enabled = true;
        ShowRTTIs();
    }
    else if (taUpdateVmtList == msg.WParam)
    {
        FillVmtList();
        InitAliases(true);
    }
    else if (taUpdateStrings == msg.WParam)
    {
        tsStrings->Enabled = true;
        miSearchString->Enabled = true;
        ShowStrings(0);
        tsNames->Enabled = true;
        ShowNames(0);
    }
    else if (taUpdateCode == msg.WParam)
    {
        tsCodeView->Enabled = true;
        bEP->Enabled = true;
        DWORD adr = CurProcAdr;
        CurProcAdr = 0;
        ShowCode(adr, lbCode->ItemIndex, -1, lbCode->TopIndex);
    }
    else if (taUpdateXrefs == msg.WParam)
    {
        lbCXrefs->Enabled = true;
        miGoTo->Enabled = true;
        miExploreAdr->Enabled = true;
        miSwitchFlag->Enabled = cbMultipleSelection->Checked;
    }
    else if (taUpdateShortClassViewer == msg.WParam)
    {
        tsClassView->Enabled = true;
        miViewClass->Enabled = true;
        miSearchVMT->Enabled = true;
        miCollapseAll->Enabled = true;

        rgViewerMode->ItemIndex = 1;
        rgViewerMode->Enabled = false;
    }
    else if (taUpdateClassViewer == msg.WParam)
    {
        FillClassViewer();
        ClassTreeDone = true;
        
        tsClassView->Enabled = true;
        miSearchVMT->Enabled = true;
        miCollapseAll->Enabled = true;

        if (ClassTreeDone && tvClassesFull->Items->Count > 0)
        {
            TTreeNode *root = tvClassesFull->Items->Item[0];
            root->Expanded = true;
            miViewClass->Enabled = true;
            rgViewerMode->ItemIndex = 0;
            rgViewerMode->Enabled = true;
        }
        else
        {
            miViewClass->Enabled = true;
            rgViewerMode->ItemIndex = 1;
            rgViewerMode->Enabled = false;
        }
        miClassTreeBuilder->Enabled = true;
    }
    else if (taUpdateBeforeClassViewer == msg.WParam)
    {
        miSearchUnit->Enabled = true;
        miRenameUnit->Enabled = true;
        miSortUnits->Enabled = true;
        miCopyList->Enabled = true;
        miKBTypeInfo->Enabled = true;
        miCtdPassword->Enabled = IsValidCodeAdr(CtdRegAdr);
        miName->Enabled = true;
        miViewProto->Enabled = true;
        miEditFunctionC->Enabled = true;
        miEditFunctionI->Enabled = true;
        miEditClass->Enabled = true;
    }
    else if (taFinished == msg.WParam)
    {
        TRACE("wm_updAnalysis: taFinished");
        AnalyzeThreadDone(0);
    }
}
/*
void __fastcall TFMain_11011981::wm_WMSysCommand(TWMSysCommand& msg)
{
    TForm::Dispatch(&msg);
    if (msg.CmdType == SC_RESTORE)
    {
        int xx = 10;
        ++xx;
    }
}
*/
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::wm_dfmOpen(TMessage& msg)
{
    TDfm* dfm = (TDfm*)msg.WParam;
    ShowDfm(dfm);
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::wm_dfmClosed(TMessage& msg)
{
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::FillClassViewer()
{
    //PVmtListRec recV;

    tvClassesFull->Items->Clear();
    const int cntVmt = VmtList->Count;
    if (!cntVmt) return;

    //FProgressBar->StartProgress("Building ClassViewer Tree", "", cntVmt);
    TStringList *tmpList = new TStringList;
    tmpList->Sorted = false;

    bool TerminatedFake = false;

    tvClassesFull->Items->BeginUpdate();

    for (int n = 0; n < cntVmt; n++)
    {
        //FProgressBar->UpdateProgress();

        //recV = (PVmtListRec)VmtList->Items[n];
        //UpdateStatusBar(GetClsName(recV->vmtAdr));
        FillClassViewerOne(n, tmpList, &TerminatedFake);
    }

    tvClassesFull->Items->EndUpdate();

    ProjectModified = true;

    delete tmpList;
    //StopProgress();
}
//---------------------------------------------------------------------------
//Fill ClassViewerTree for 1 class
void __fastcall TFMain_11011981::FillClassViewerOne(int n, TStringList* tmpList, const bool* terminated)
{
    bool        vmtProc;
    int         m, size, sizeParent, pos, cnt, vmtOfs, _pos;
    DWORD       vmtAdr, vmtAdrParent, vAdr, iAdr;
    ULONGLONG   _rcx;
    TTreeNode   *rootNode, *node;
    String      className, nodeTextParent, nodeText, line, name;
    PInfoRec    recN;
    PMethodRec  recM;
    PVmtListRec recV;
    DISINFO     disInfo;

    recV = (PVmtListRec)VmtList->Items[n];
    vmtAdr = recV->vmtAdr;

    className = GetClsName(vmtAdr);
    size = GetClassSize(vmtAdr); size += 4;

    vmtAdrParent = GetParentAdr(vmtAdr);
    sizeParent = GetClassSize(vmtAdrParent); sizeParent += 4;

    nodeTextParent = GetParentName(vmtAdr) + " #" + Val2Str8(vmtAdrParent) + " Sz=" + Val2Str1(sizeParent);
    nodeText = className + " #" + Val2Str8(vmtAdr) + " Sz=" + Val2Str1(size);
    node = FindTreeNodeByName(nodeTextParent);
    node = AddClassTreeNode(node, nodeText);

    rootNode = node;

    if (rootNode)
    {
        //Interfaces
        const int intfsNum = LoadIntfTable(vmtAdr, tmpList);
        if (intfsNum)
        {
            for (m = 0; m < intfsNum && !*terminated; m++)
            {
                nodeText = tmpList->Strings[m];
                sscanf(nodeText.c_str(), "%lX", &vAdr);
                if (IsValidCodeAdr(vAdr))
                {
                    TTreeNode *intfsNode = AddClassTreeNode(rootNode, "<I> " + nodeText.SubString(nodeText.Pos(' ') + 1, nodeText.Length()));
                    cnt = 0;
                    pos = Adr2Pos(vAdr);
                    for (int v = 0;;v += 8)
                    {
                        if (idr.IsFlagSet(cfVTable, pos)) cnt++;
                        if (cnt == 2) break;
                        iAdr = *((DWORD*)(Code + pos));
                        DWORD _adr = iAdr;
                        _pos = Adr2Pos(_adr);
                        vmtProc = false; vmtOfs = 0;
                        _rcx = 0;
                        while (1)
                        {
                            int instrlen = GetDisasm().Disassemble(Code + _pos, (__int64)_adr, &disInfo, 0);
                            if ((disInfo.OpType[0] == otMEM || disInfo.OpType[1] == otMEM) &&
                                disInfo.BaseReg != REG_RSP)//to exclude instruction "xchg reg, [esp]"
                            {
                                vmtOfs = disInfo.Offset;
                            }
                            if (disInfo.OpType[0] == otREG && disInfo.OpType[1] == otIMM)
                            {
                                if (disInfo.OpRegIdx[0] == REG_RCX)
                                    _rcx = disInfo.Immediate;
                            }
                            if (disInfo.Call)
                            {
                                ShowMessage("Call inside interface entry");
                                /*
                                recN = GetInfoRec(disInfo.Immediate);
                                if (recN)
                                {
                                    if (recN->SameName("@CallDynaInst") ||
                                        recN->SameName("@CallDynaClass"))
                                    {
                                        GetDynaInfo(vmtAdr, _si, &iAdr);
                                        break;
                                    }
                                    else if (recN->SameName("@FindDynaInst") ||
                                             recN->SameName("@FindDynaClass"))
                                    {
                                        GetDynaInfo(vmtAdr, _dx, &iAdr);
                                        break;
                                    }
                                }
                                */
                            }
                            if (disInfo.Branch && !disInfo.Conditional)
                            {
                                if (IsValidImageAdr(disInfo.Immediate))
                                {
                                    iAdr = disInfo.Immediate;
                                }
                                else
                                {
                                    vmtProc = true;
                                    iAdr = *((DWORD*)(Code + Adr2Pos(vmtAdr - Vmt.SelfPtr + vmtOfs)));
                                    recM = GetMethodInfo(vmtAdr, 'V', vmtOfs);
                                    if (recM) name = recM->name;
                                }
                                break;
                            }
                            else if (disInfo.Ret)
                            {
                                vmtProc = true;
                                iAdr = *((DWORD*)(Code + Adr2Pos(vmtAdr - Vmt.SelfPtr + vmtOfs)));
                                recM = GetMethodInfo(vmtAdr, 'V', vmtOfs);
                                if (recM) name = recM->name;
                                break;
                            }
                            _pos += instrlen; _adr += instrlen;
                        }
                        if (!vmtProc && IsValidImageAdr(iAdr))
                        {
                            recN = GetInfoRec(iAdr);
                            if (recN && recN->HasName())
                                name = recN->GetName();
                            else
                                name = "";
                        }
                        line = "I" + Val2Str4(v) + " #" + Val2Str8(iAdr);
                        if (name != "") line += " " + name;
                        AddClassTreeNode(intfsNode, line);
                        pos += 8;
                    }
                }
                else
                {
                    TTreeNode *intfsNode = AddClassTreeNode(rootNode, "<I> " + nodeText);
                }
            }
        }
        if (*terminated) return;
        //Automated
        const int autoNum = LoadAutoTable(vmtAdr, tmpList);
        if (autoNum)
        {
            nodeText = "<A>";
            TTreeNode* autoNode = AddClassTreeNode(rootNode, nodeText);
            for (m = 0; m < autoNum && !*terminated; m++)
            {
                nodeText = tmpList->Strings[m];
                AddClassTreeNode(autoNode, nodeText);
            }
        }
        /*
        //Fields
        const int fieldsNum = form->LoadFieldTable(vmtAdr, fieldsList);
        if (fieldsNum)
        {
            node = rootNode;
            nodeText = "<F>";
            //node = form->tvClassesFull->Items->AddChild(node, nodeText);
            node = AddClassTreeNode(node, nodeText);
            TTreeNode* fieldsNode = node;
            for (m = 0; m < fieldsNum && !Terminated; m++)
            {
                //node = fieldsNode;
                PFIELDINFO fInfo = (PFIELDINFO)fieldsList->Items[m];
                nodeText = Val2Str5(fInfo->Offset) + " ";
                if (fInfo->Name != "")
                    nodeText += fInfo->Name;
                else
                    nodeText += "?";
                nodeText += ":";
                if (fInfo->Type != "")
                    nodeText += fInfo->Type;
                else
                    nodeText += "?";

                //node = form->tvClassesFull->Items->AddChild(node, nodeText);
                AddClassTreeNode(fieldsNode, nodeText);
            }
        }
        */
        if (*terminated) return;
        //Events
        const int methodsNum = LoadMethodTable(vmtAdr, tmpList);
        if (methodsNum)
        {
            nodeText = "<E>";
            TTreeNode* methodsNode = AddClassTreeNode(rootNode, nodeText);
            for (m = 0; m < methodsNum && !*terminated; m++)
            {
                nodeText = tmpList->Strings[m];
                AddClassTreeNode(methodsNode, nodeText);
            }
        }
        if (*terminated) return;
        //Dynamics
        const int dynamicsNum = LoadDynamicTable(vmtAdr, tmpList);
        if (dynamicsNum)
        {
            nodeText = "<D>";
            TTreeNode* dynamicsNode = AddClassTreeNode(rootNode, nodeText);
            for (m = 0; m < dynamicsNum && !*terminated; m++)
            {
                nodeText = tmpList->Strings[m];
                AddClassTreeNode(dynamicsNode, nodeText);
            }
        }
        if (*terminated) return;
        //Virtual
        const int virtualsNum = LoadVirtualTable(vmtAdr, tmpList);
        if (virtualsNum)
        {
            nodeText = "<V>";
            TTreeNode* virtualsNode = AddClassTreeNode(rootNode, nodeText);
            for (m = 0; m < virtualsNum && !*terminated; m++)
            {
                nodeText = tmpList->Strings[m];
                AddClassTreeNode(virtualsNode, nodeText);
            }
        }
    }
}
//---------------------------------------------------------------------------
TTreeNode* __fastcall TFMain_11011981::AddClassTreeNode(TTreeNode* node, String nodeText)
{
    TTreeNode* newNode = 0;
    if (!node)  //Root
        newNode = tvClassesFull->Items->Add(0, nodeText);
    else
        newNode = tvClassesFull->Items->AddChild(node, nodeText);

    AddTreeNodeWithName(newNode, nodeText);

    return newNode;
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::OutputDecompilerHeader(FILE* f)
{
    int n = sprintf(StringBuf, "IDR home page: http://kpnc.org/idr32/en");
    int m = sprintf(StringBuf, "Decompiled by IDR64 v.%s", idr.GetVersion().c_str());
    if (n < m) n = m;
    
    memset(StringBuf, '*', n); StringBuf[n] = 0;
    fprintf(f, "//%s\n", StringBuf);

    fprintf(f, "//IDR home page: http://kpnc.org/idr32/en\n", StringBuf);

    sprintf(StringBuf, "Decompiled by IDR v.%s", idr.GetVersion().c_str());
    fprintf(f, "//%s\n", StringBuf);

    memset(StringBuf, '*', n); StringBuf[n] = 0;
    fprintf(f, "//%s\n", StringBuf);
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::miSaveDelphiProjectClick(TObject *Sender)
{
    bool            typePresent, _isForm, comment;
    BYTE            kind;
    int             n, m, k, num, dotpos, len, minValue, maxValue;
    DWORD           adr, adr1, parentAdr;
    FILE            *f;
    TList           *tmpList;
    TStringList     *intBodyLines;
    TStringList     *intUsesLines;
    //TStringList     *impBodyLines;
    //TStringList     *impUsesLines;
    TStringList     *unitsList;
    TStringList     *formList;
    TStringList     *publishedList;
    TStringList     *publicList;
    TSearchRec      sr;
    PUnitRec        recU;
    PInfoRec        recN;
    PFIELDINFO      fInfo;
    PMethodRec      recM;
    PVmtListRec     recV;
    TDfm            *dfm;
    PComponentInfo  cInfo;
    String          curDir, DelphiProjectPath;
    String          unitName, className, parentName, fieldName, typeName;
    String          procName, formName, dfmName, line, uName;

    curDir = GetCurrentDir();
    DelphiProjectPath = AppDir + "Projects";
    if (DirectoryExists(DelphiProjectPath))
    {
        ChDir(DelphiProjectPath);
        if (!FindFirst("*.*", faArchive, sr))
        {
            do
            {
                DeleteFile(sr.Name);
            } while (!FindNext(sr));

            FindClose(sr);
        }
    }
    else
    {
        if (!CreateDir(DelphiProjectPath)) return;
        ChDir(DelphiProjectPath);
    }
    
    BusyCursor  cursor;
    
    //Save Forms
    for (n = 0; n < idr.ResInfo()->GetDfmCount(); n++)
    {
    	dfm = idr.ResInfo()->GetDfm(n);
        formList = new TStringList;
        idr.ResInfo()->GetFormAsText(dfm, formList);
        dfmName = dfm->Name;
        //If system name add F at start
        if (SameText(dfmName, "prn")) dfmName = "F" + dfmName;
        formList->SaveToFile(dfmName + ".dfm");
        delete formList;
    }

    unitsList = new TStringList;

    for (n = 0; n < UnitsNum; n++)
    {
        recU = (PUnitRec)Units->Items[n];
        if (recU->trivial) continue;
        typePresent = false;
        _isForm = false;
        unitName = GetUnitName(recU);
        tmpList = new TList;
        intBodyLines = new TStringList;
        intUsesLines = new TStringList;
        //impBodyLines = new TStringList;
        //impUsesLines = new TStringList;
        publishedList = new TStringList;
        publicList = new TStringList;

        intUsesLines->Add("SysUtils");
        intUsesLines->Add("Classes");
        for (adr = recU->fromAdr; adr < recU->toAdr; adr++)
        {
            recN = GetInfoRec(adr);
            if (!recN) continue;

            kind = recN->kind;
            switch (kind)
            {
            case ikEnumeration:
            case ikSet:
            case ikMethod:
            case ikArray:
            case ikRecord:
            case ikDynArray:
                typePresent = true;
                line = FTypeInfo_11011981->GetRTTI(adr);
                len = sprintf(StringBuf, "  %s = %s;", recN->GetName().c_str(), line.c_str());
                intBodyLines->Add(String(StringBuf, len));
                break;
            //class
            case ikVMT:
                typePresent = true;
                className = recN->GetName();
                publishedList->Clear();
                publicList->Clear();

                dfm = idr.ResInfo()->GetFormByClassName(className);
                if (dfm)
                {
                    _isForm = true;
                    len = sprintf(StringBuf, "%s in '%s.pas' {%s}", unitName, unitName, dfm->Name);
                    unitsList->Add(String(StringBuf, len));
                }

                parentAdr = GetParentAdr(adr);
                parentName = GetClsName(parentAdr);
                len = sprintf(StringBuf, "  %s = class(%s)", className.c_str(), parentName.c_str());
                intBodyLines->Add(String(StringBuf, len));

                num = LoadFieldTable(adr, tmpList);
                for (m = 0; m < num; m++)
                {
                    fInfo = (PFIELDINFO)tmpList->Items[m];
                    if (fInfo->Name != "")
                        fieldName = fInfo->Name;
                    else
                        fieldName = "f" + Val2Str0(fInfo->Offset);
                    if (fInfo->Type != "")
                    {
                        comment = false;
                        typeName = TrimTypeName(fInfo->Type);
                    }
                    else
                    {
                        comment = true;
                        typeName = "?";
                    }
                    //Add UnitName to UsesList if necessary
                    for (k = 0; k < VmtList->Count; k++)
                    {
                        recV = (PVmtListRec)VmtList->Items[k];
                        if (recV && SameText(typeName, recV->vmtName))
                        {
                            uName = GetUnitName(recV->vmtAdr);
                            if (intUsesLines->IndexOf(uName) == -1)
                                intUsesLines->Add(uName);
                            break;
                        }
                    }
                    
                    if (!comment)
                        len = sprintf(StringBuf, "    %s:%s;//f%X", fieldName.c_str(), typeName.c_str(), fInfo->Offset);
                    else
                        len = sprintf(StringBuf, "    //%s:%s;//f%X", fieldName.c_str(), typeName.c_str(), fInfo->Offset);
                    if (_isForm && dfm && dfm->IsFormComponent(fieldName))
                        publishedList->Add(String(StringBuf, len));
                    else
                        publicList->Add(String(StringBuf, len));

                }

                num = LoadMethodTable(adr, tmpList);
                for (m = 0; m < num; m++)
                {
                    recM = (PMethodRec)tmpList->Items[m];
                    recN = GetInfoRec(recM->address);
                    procName = recN->MakePrototype(recM->address, true, false, false, false, false);
                    if (!procName.Pos(":?"))
                        len = sprintf(StringBuf, "    %s", procName);
                    else
                        len = sprintf(StringBuf, "    //%s", procName);
                    publishedList->Add(String(StringBuf, len));
                }

                num = LoadVirtualTable(adr, tmpList);
                for (m = 0; m < num; m++)
                {
                    recM = (PMethodRec)tmpList->Items[m];
                    //Check if procadr from other class
                    if (!IsOwnVirtualMethod(adr, recM->address)) continue;

                    recN = GetInfoRec(recM->address);
                    procName = recN->MakeDelphiPrototype(recM->address, recM);

                    len = sprintf(StringBuf, "    ");
                    if (procName.Pos(":?")) len += sprintf(StringBuf + len, "//");
                    len += sprintf(StringBuf + len, "%s", procName.c_str());
                    if (recM->id >= 0) len += sprintf(StringBuf + len, "//v%X", recM->id);
                    len += sprintf(StringBuf + len, "//%08lX", recM->address);

                    publicList->Add(String(StringBuf, len));
                }

                num = LoadDynamicTable(adr, tmpList);
                for (m = 0; m < num; m++)
                {
                    recM = (PMethodRec)tmpList->Items[m];
                    recN = GetInfoRec(recM->address);
                    procName = recN->MakePrototype(recM->address, true, false, false, false, false);
                    PMsgMInfo _info = GetMsgInfo(recM->id);
                    if (_info && _info->msgname != "")
                    {
                        procName += String(" message ") + _info->msgname + ";";
                    }
                    else
                        procName += " dynamic;";

                    if (!procName.Pos(":?"))
                        len = sprintf(StringBuf, "    %s", procName.c_str());
                    else
                        len = sprintf(StringBuf, "    //%s", procName.c_str());
                    publicList->Add(String(StringBuf, len));
                }

                if (publishedList->Count)
                {
                    intBodyLines->Add("  published");
                    for (m = 0; m < publishedList->Count; m++)
                    {
                        intBodyLines->Add(publishedList->Strings[m]);
                    }
                }
                if (publicList->Count)
                {
                    intBodyLines->Add("  public");
                    for (m = 0; m < publicList->Count; m++)
                    {
                        intBodyLines->Add(publicList->Strings[m]);
                    }
                }

                for (adr1 = recU->fromAdr; adr1 < recU->toAdr; adr1++)
                {
                    //Skip Initialization and Finalization procs
                    if (adr1 == recU->iniadr || adr1 == recU->finadr) continue;
                    recN = GetInfoRec(adr1);
                    if (!recN || !recN->procInfo) continue;
                    dotpos = recN->GetName().Pos(".");
                    if (!dotpos || !SameText(className, recN->GetName().SubString(1, dotpos - 1))) continue;
                    if ((recN->procInfo->flags & PF_VIRTUAL) ||
                        (recN->procInfo->flags & PF_DYNAMIC) ||
                        (recN->procInfo->flags & PF_EVENT))
                        continue;

                    if (recN->kind == ikConstructor || (recN->procInfo->flags & PF_METHOD))
                    {
                        procName = recN->MakePrototype(adr1, true, false, false, false, false);
                        if (!procName.Pos(":?"))
                            len = sprintf(StringBuf, "    %s", procName.c_str());
                        else
                            len = sprintf(StringBuf, "    //%s", procName.c_str());
                        if (intBodyLines->IndexOf(String(StringBuf, len)) == -1)
                            intBodyLines->Add(String(StringBuf, len));
                    }
                }
                intBodyLines->Add("  end;");
                break;
            }
        }
        //Output information
        f = fopen((unitName + ".pas").c_str(), "wt+");
        OutputDecompilerHeader(f);
        fprintf(f, "unit %s;\n\n", unitName);
        fprintf(f, "interface\n");
        //Uses
        if (intUsesLines->Count)
        {
            fprintf(f, "\nuses\n  ");
            for (m = 0; m < intUsesLines->Count; m++)
            {
                if (m) fprintf(f, ", ");
                fprintf(f, "%s", intUsesLines->Strings[m].c_str());
            }
            fprintf(f, ";\n\n");
        }
        //Type
        if (typePresent) fprintf(f, "type\n");
        for (m = 0; m < intBodyLines->Count; m++)
        {
            fprintf(f, "%s\n", intBodyLines->Strings[m].c_str());
        }
        //Other procs (not class members)
        for (adr = recU->fromAdr; adr < recU->toAdr; adr++)
        {
            //Skip Initialization and Finalization procs
            if (adr == recU->iniadr || adr == recU->finadr) continue;

            recN = GetInfoRec(adr);
            if (!recN || !recN->procInfo) continue;

            procName = recN->MakePrototype(adr, true, false, false, false, false);
            if (!procName.Pos(":?"))
                len = sprintf(StringBuf, "    %s", procName.c_str());
            else
                len = sprintf(StringBuf, "    //%s", procName.c_str());

            if (intBodyLines->IndexOf(String(StringBuf, len)) != -1) continue;

            fprintf(f, "%s\n", StringBuf);
        }

        fprintf(f, "\nimplementation\n\n");
        if (_isForm) fprintf(f, "{$R *.DFM}\n\n");
        for (adr = recU->fromAdr; adr < recU->toAdr; adr++)
        {
            //Initialization and Finalization procs
            if (adr == recU->iniadr || adr == recU->finadr) continue;

            recN = GetInfoRec(adr);
            if (!recN || !recN->procInfo) continue;

            kind = recN->kind;
            if (kind == ikConstructor ||
                kind == ikDestructor  ||
                kind == ikProc        ||
                kind == ikFunc)
            {
                fprintf(f, "//%08lX\n", adr);
                procName = recN->MakePrototype(adr, true, false, false, true, false);
                if (!procName.Pos(":?"))
                {
                    fprintf(f, "%s\n", procName);
                    fprintf(f, "begin\n");
                    fprintf(f, "{*\n");
                    OutputCode(f, adr, "", false);
                    fprintf(f, "*}\n");
                    fprintf(f, "end;\n\n");
                }
                else
                {
                    fprintf(f, "{*%s\n", procName);
                    fprintf(f, "begin\n");
                    OutputCode(f, adr, "", false);
                    fprintf(f, "end;*}\n\n");
                }
            }
        }

        if (!recU->trivialIni || !recU->trivialFin)
        {
            fprintf(f, "Initialization\n");
            if (!recU->trivialIni)
            {
                fprintf(f, "//%08lX\n", recU->iniadr);
                fprintf(f, "{*\n");
                OutputCode(f, recU->iniadr, "", false);
                fprintf(f, "*}\n");
            }
            fprintf(f, "Finalization\n");
            if (!recU->trivialFin)
            {
                fprintf(f, "//%08lX\n", recU->finadr);
                fprintf(f, "{*\n");
                OutputCode(f, recU->finadr, "", false);
                fprintf(f, "*}\n");
            }
        }

        fprintf(f, "end.");
        fclose(f);

        delete tmpList;
        delete intBodyLines;
        delete intUsesLines;
        //delete impBodyLines;
        //delete impUsesLines;
        delete publishedList;
        delete publicList;
    }
    //dpr
    recU = (PUnitRec)Units->Items[UnitsNum - 1];
    unitName = recU->names->Strings[0];
    f = fopen((unitName + ".dpr").c_str(), "wt+");

    OutputDecompilerHeader(f);

    if (SourceIsLibrary)
        fprintf(f, "library %s;\n\n", unitName);
    else
        fprintf(f, "program %s;\n\n", unitName);

    fprintf(f, "uses\n");
    fprintf(f, "  SysUtils, Classes;\n\n");

    fprintf(f, "{$R *.res}\n\n");

    if (SourceIsLibrary)
    {
        bool _expExists = false;
        for (n = 0; n < ExpFuncList->Count; n++)
        {
            PExportNameRec recE = (PExportNameRec)ExpFuncList->Items[n];
            adr = recE->address;
            if (IsValidImageAdr(adr))
            {
                fprintf(f, "//%08lX\n", adr);
                recN = GetInfoRec(adr);
                if (recN)
                {
                    fprintf(f, "%s\n", recN->MakePrototype(adr, true, false, false, true, false));
                    fprintf(f, "begin\n");
                    fprintf(f, "{*\n");
                    OutputCode(f, adr, "", false);
                    fprintf(f, "*}\n");
                    fprintf(f, "end;\n\n");
                    _expExists = true;
                }
                else
                {
                    fprintf(f, "//No information\n\n");
                }
            }
        }
        if (_expExists)
        {
            fprintf(f, "exports\n");
            for (n = 0; n < ExpFuncList->Count; n++)
            {
                PExportNameRec recE = (PExportNameRec)ExpFuncList->Items[n];
                adr = recE->address;
                if (IsValidImageAdr(adr))
                {
                    recN = GetInfoRec(adr);
                    if (recN)
                    {
                        fprintf(f, "%s", recN->GetName());
                        if (n < ExpFuncList->Count - 1) fprintf(f, ",\n");
                    }
                }
            }
            fprintf(f, ";\n\n");
        }
    }

    fprintf(f, "//%08lX\n", EP);
    fprintf(f, "begin\n");
    fprintf(f, "{*\n");
    OutputCode(f, EP, "", false);
    fprintf(f, "*}\n");
    fprintf(f, "end.\n");
    fclose(f);

    delete unitsList;

    ChDir(curDir);
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::bDecompileClick(TObject *Sender)
{
    int procSize = GetProcSize(CurProcAdr);
    if (procSize > 0)
    {
        TDecompileEnv *DeEnv = new TDecompileEnv(CurProcAdr, procSize, GetInfoRec(CurProcAdr));
        try
        {
            DeEnv->DecompileProc();
        }
        catch(Exception &exception)
        {
            ShowCode(DeEnv->StartAdr, DeEnv->ErrAdr, lbCXrefs->ItemIndex, -1);
            Application->ShowException(&exception);
        }
        lbSourceCode->Clear();
        DeEnv->OutputSourceCode();
        if (DeEnv->Alarm)
            tsSourceCode->Highlighted = true;
        else
            tsSourceCode->Highlighted = false;
        if (!DeEnv->ErrAdr)
            pcWorkArea->ActivePage = tsSourceCode;
        delete DeEnv;
    }
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::miHex2DoubleClick(TObject *Sender)
{
    FHex2DoubleDlg_11011981->ShowModal();
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::acFontAllExecute(TObject *Sender)
{
    FontsDlg->Font->Assign(lbCode->Font);
    if (FontsDlg->Execute()) SetupAllFonts(FontsDlg->Font);
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::SetupAllFonts(TFont* font)
{
    TListBox* formListBoxes[] =
    {
      lbUnits,
      lbRTTIs,
      lbForms,
      lbAliases,
      lbCode,
      lbStrings,
      lbNames,
      lbNXrefs,
      lbSXrefs,
      lbCXrefs,
      lbSourceCode,
      lbUnitItems,
      0
    };

    TTreeView* formTreeViews[] =
    {
      tvClassesShort,
      tvClassesFull,
      0
    };

    for (int n = 0; formListBoxes[n]; n++)
    {
        formListBoxes[n]->Font->Assign(font);
    }

    for (int n = 0; formTreeViews[n]; n++)
    {
        formTreeViews[n]->Font->Assign(font);
    }
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::pmUnitItemsPopup(TObject *Sender)
{
    miEditFunctionI->Enabled = (lbUnitItems->ItemIndex >= 0);
    miCopyAddressI->Enabled = (lbUnitItems->ItemIndex >= 0);
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::CopyAddress(String line, int ofs, int bytes)
{
    char    buf[9], *p = buf;

    Clipboard()->Open();
    for (int n = 1; n <= bytes; n++)
    {
        *p = line[n + ofs]; p++;
    }
    *p = 0;
    Clipboard()->SetTextBuf(buf);
    Clipboard()->Close();
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::miCopyAddressCodeClick(TObject *Sender)
{
    int bytes = (lbCode->ItemIndex) ? 8 : 0;
    CopyAddress(lbCode->Items->Strings[lbCode->ItemIndex], 1, bytes);
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::miCopySource2ClipboardClick(TObject *Sender)
{
    Copy2Clipboard(lbSourceCode->Items, 0, false);
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::pmCodePopup(TObject *Sender)
{
    int         _ap;
    DWORD       _adr;
    DISINFO     _disInfo;

    miXRefs->Enabled = false;
    miXRefs->Clear();

    if (ActiveControl == lbCode)
    {
        if (lbCode->ItemIndex <= 0) return;
        DWORD   adr;
        sscanf(lbCode->Items->Strings[lbCode->ItemIndex].c_str() + 2, "%lX", &adr);
        if (adr != CurProcAdr && idr.IsFlagSet(cfLoc, Adr2Pos(adr)))
        {
            PInfoRec recN = GetInfoRec(adr);
            if (recN && recN->xrefs && recN->xrefs->Count > 0)
            {
                miXRefs->Enabled = true;
                miXRefs->Clear();
                for (int n = 0; n < recN->xrefs->Count; n++)
                {
                    PXrefRec recX = (PXrefRec)recN->xrefs->Items[n];
                    _adr = recX->adr + recX->offset;
                    _ap = Adr2Pos(_adr);
                    GetDisasm().Disassemble(Code + _ap, (__int64)_adr, &_disInfo, 0);
                    TMenuItem* mi = new TMenuItem(pmCode);
                    mi->Caption = Val2Str8(_adr) + " " + GetDisasm().GetMnemonic(_disInfo.MnemIdx);
                    mi->Tag = _adr;
                    mi->OnClick = GoToXRef;
                    miXRefs->Add(mi);
                }
            }
        }
    }
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::GoToXRef(TObject *Sender)
{
    TMenuItem* mi = (TMenuItem*)Sender;
    DWORD Adr = mi->Tag;
    if (Adr && IsValidCodeAdr(Adr))
    {
        PROCHISTORYREC rec;

        rec.adr = CurProcAdr;
        rec.itemIdx = lbCode->ItemIndex;
        rec.xrefIdx = lbCXrefs->ItemIndex;
        rec.topIdx = lbCode->TopIndex;
        ShowCode(CurProcAdr, Adr, lbCXrefs->ItemIndex, -1);
        CodeHistoryPush(&rec);
    }
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::lbFormsClick(TObject *Sender)
{
    FormsSearchFrom = lbForms->ItemIndex;
    WhereSearch = SEARCH_FORMS;
}
//---------------------------------------------------------------------------

void __fastcall TFMain_11011981::lbCodeClick(TObject *Sender)
{
    WhereSearch = SEARCH_CODEVIEWER;

    if (lbCode->ItemIndex <= 0) return;
    
    String prevItem = SelectedAsmItem;
    SelectedAsmItem = "";
    String text = lbCode->Items->Strings[lbCode->ItemIndex];
    int textLen = text.Length();

    int x = lbCode->ScreenToClient(Mouse->CursorPos).x;
    for (int n = 1, wid = 0; n <= textLen; n++)
    {
        if (wid >= x)
        {
            char c;
            int beg = n;
            while (beg >= 1)
            {
                c = text[beg];
                if (!isalpha(c) && !isdigit(c) && c != '@')
                {
                    beg++;
                    break;
                }
                beg--;
            }
            int end = beg;
            while (end <= textLen)
            {
                c = text[end];
                if (!isalpha(c) && !isdigit(c) && c != '@')
                {
                    end--;
                    break;
                }
                end++;
            }
            SelectedAsmItem = text.SubString(beg, end - beg + 1);
            break;
        }
        wid += lbCode->Canvas->TextWidth(text[n]);
    }
    if (SelectedAsmItem != prevItem)
        lbCode->Invalidate();
}
//---------------------------------------------------------------------------

void __fastcall TFMain_11011981::pcInfoChange(TObject *Sender)
{
    switch (pcInfo->TabIndex)
    {
      case 0: WhereSearch = SEARCH_UNITS;
      break;
      case 1: WhereSearch = SEARCH_RTTIS;
      break;
      case 2: WhereSearch = SEARCH_FORMS;
      break;
    }
}
//---------------------------------------------------------------------------

void __fastcall TFMain_11011981::pcWorkAreaChange(TObject *Sender)
{
    switch (pcWorkArea->TabIndex)
    {
      case 0: WhereSearch = SEARCH_CODEVIEWER;
      break;
      case 1: WhereSearch = SEARCH_CLASSVIEWER;
      break;
      case 2: WhereSearch = SEARCH_STRINGS;
      break;
      case 3: WhereSearch = SEARCH_NAMES;
      break;
      case 4: WhereSearch = SEARCH_SOURCEVIEWER;
      break;      
    }
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::miSearchFormClick(TObject *Sender)
{
    WhereSearch = SEARCH_FORMS;

    FindDlg_11011981->cbText->Clear();
    for (int n = 0; n < FormsSearchList->Count; n++)
        FindDlg_11011981->cbText->AddItem(FormsSearchList->Strings[n], 0);

    if (FindDlg_11011981->ShowModal() == mrOk && FindDlg_11011981->cbText->Text != "")
    {
        if (lbForms->ItemIndex == -1)
            FormsSearchFrom = 0;
        else
            FormsSearchFrom = lbForms->ItemIndex;

        FormsSearchText = FindDlg_11011981->cbText->Text;
        if (FormsSearchList->IndexOf(FormsSearchText) == -1) FormsSearchList->Add(FormsSearchText);
        FindText(FormsSearchText);
    }
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::miSearchNameClick(TObject *Sender)
{
    WhereSearch = SEARCH_NAMES;

    FindDlg_11011981->cbText->Clear();
    for (int n = 0; n < NamesSearchList->Count; n++)
        FindDlg_11011981->cbText->AddItem(NamesSearchList->Strings[n], 0);

    if (FindDlg_11011981->ShowModal() == mrOk && FindDlg_11011981->cbText->Text != "")
    {
        if (lbNames->ItemIndex == -1)
            NamesSearchFrom = 0;
        else
            NamesSearchFrom = lbNames->ItemIndex;

        NamesSearchText = FindDlg_11011981->cbText->Text;
        if (NamesSearchList->IndexOf(NamesSearchText) == -1) NamesSearchList->Add(NamesSearchText);
        FindText(NamesSearchText);
    }
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::miPluginsClick(TObject *Sender)
{
    String PluginsPath = AppDir + "Plugins";
    if (!DirectoryExists(PluginsPath))
    {
        if (!CreateDir(PluginsPath))
        {
            //ShowMessage("Cannot create subdirectory for plugins");
            LogMessage("Cannot create subdirectory for plugins: "+PluginsPath, MB_ICONWARNING);
            return;
        }
    }

    idr.ResInfo()->FreeFormPlugin();
    FPlugins->PluginsPath = PluginsPath;
    FPlugins->PluginName = "";
    if (FPlugins->ShowModal() == mrOk)
        idr.ResInfo()->SetFormPluginName(FPlugins->PluginName);
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::miCopyStringsClick(TObject *Sender)
{
    Copy2Clipboard(lbStrings->Items, 0, false);
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::miViewAllClick(TObject *Sender)
{
;
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::lbSourceCodeMouseMove(TObject *Sender,
      TShiftState Shift, int X, int Y)
{
    if (lbSourceCode->CanFocus()) ActiveControl = lbSourceCode;
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::cbMultipleSelectionClick(TObject *Sender)
{
//    lbCode->MultiSelect = cbMultipleSelection->Checked;
//    miSwitchFlag->Enabled = cbMultipleSelection->Checked;
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::lbSourceCodeDrawItem(TWinControl *Control,
      int Index, TRect &Rect, TOwnerDrawState State)
{
/*
*/
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::miSwitchSkipFlagClick(TObject *Sender)
{
    DWORD   _adr;

    if (lbCode->SelCount > 0)
    {
        for (int n = 0; n < lbCode->Count; n++)
        {
            if (lbCode->Selected[n])
            {
                sscanf(lbCode->Items->Strings[n].c_str() + 2, "%lX", &_adr);
                idr.XorFlag((cfDSkip | cfSkip), Adr2Pos(_adr));;
            }
        }
        RedrawCode();
        ProjectModified = true;
    }
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::miSwitchFrameFlagClick(TObject *Sender)
{
    DWORD   _adr;

    if (lbCode->SelCount > 0)
    {
        for (int n = 0; n < lbCode->Count; n++)
        {
            if (lbCode->Selected[n])
            {
                sscanf(lbCode->Items->Strings[n].c_str() + 2, "%lX", &_adr);
                idr.XorFlag(cfFrame, Adr2Pos(_adr));
            }
        }
        RedrawCode();
        ProjectModified = true;
    }
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::miProcessDumperClick(TObject *Sender)
{
    FActiveProcesses->ShowProcesses();
    FActiveProcesses->ShowModal();
}
//---------------------------------------------------------------------------
int __fastcall ArgsCmpFunction(void *item1, void *item2)
{
    PARGINFO rec1 = (PARGINFO)item1;
    PARGINFO rec2 = (PARGINFO)item2;

    if (rec1->Ndx > rec2->Ndx) return 1;
    if (rec1->Ndx < rec2->Ndx) return -1;
    return 0;
}
//---------------------------------------------------------------------------
int __fastcall ExportsCmpFunction(void *item1, void *item2)
{
    PExportNameRec rec1 = (PExportNameRec)item1;
    PExportNameRec rec2 = (PExportNameRec)item2;
    if (rec1->address > rec2->address) return 1;
    if (rec1->address < rec2->address) return -1;
    return 0;
}
//---------------------------------------------------------------------------
int __fastcall ImportsCmpFunction(void *item1, void *item2)
{
    PImportNameRec rec1 = (PImportNameRec)item1;
    PImportNameRec rec2 = (PImportNameRec)item2;
    if (rec1->address > rec2->address) return 1;
    if (rec1->address < rec2->address) return -1;
    return 0;
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::LogMessage(const AnsiString& msg, const int flags)
{
    if (!quietMode)
        Application->MessageBox(msg.c_str(), Caption.c_str(), flags);

    //TODO: copy message to some log file or mainform status bar?...
}
//---------------------------------------------------------------------------
void __fastcall TFMain_11011981::AppEventsRestore(TObject *Sender)
{
    //there is a mystery in a following case:
    // app is under analysis, user minimyze main form,
    // analysis finished, user restores app and sees frozen progress form!
    // the only way to hide it seems to do the following:
    if (!AnalyzeThread)
    {
        //FProgressBar->Hide(); //this does not work!
        ShowWindow(FProgressBar->Handle, SW_HIDE);
    }
}
//---------------------------------------------------------------------------


