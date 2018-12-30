//---------------------------------------------------------------------------
#ifndef MiscH
#define MiscH
//---------------------------------------------------------------------------
#include <Classes.hpp>
#include <Forms.hpp>
#include "SyncObjs.hpp"
#include "Decompiler.h"
//---------------------------------------------------------------------------
//this macro calculates any array size (in compile time)
#define ARRAYSIZE(a) \
  ((sizeof(a) / sizeof(*(a))) / \
  static_cast<size_t>(!(sizeof(a) % sizeof(*(a)))))

#define SYSPROCSNUM 7
#define SYSINITPROCSNUM 2

//Float Type
#define     FT_SINGLE       1
#define     FT_DOUBLE       2
#define     FT_EXTENDED     3
#define     FT_REAL         4
#define     FT_COMP         5
#define     FT_CURRENCY     6

//Some common global values widely used in different modules
#define     MAXSTRBUFFER        10000
#define     MAX_DISASSEMBLE     250000
//---------------------------------------------------------------------------
//GUI updating messages
#define WM_UPDANALYSISSTATUS    WM_USER + 100
#define WM_DFMOPEN              WM_USER + 101
#define WM_DFMCLOSED            WM_USER + 102
#define WM_SHOWCODE             WM_USER + 103
#define WM_SHOWCLASSVIEWER      WM_USER + 104
//---------------------------------------------------------------------------

//enum OrdType {OtSByte, OtUByte, OtSWord, OtUWord, OtSLong, OtULong};

enum FloatType {FtSingle, FtDouble, FtExtended, FtComp, FtCurr
};

enum MethodKind {MkProcedure, MkFunction, MkConstructor, MkDestructor,
                 MkClassProcedure, MkClassFunction
};

#define PfVar       0x1
#define PfConst     0x2
#define PfArray     0x4
#define PfAddress   0x8
#define PfReference 0x10
#define PfOut       0x20

enum IntfFlag {IfHasGuid, IfDispInterface, IfDispatch
};

//---------------------------------------------------------------------------
//template class to free resources in any list
//including list itself
//
template<class T>
void CleanupList(TList* list)
{
    if (list)
    {
        for (int i = 0; i < list->Count; ++i)
        {
            T* item = (T*)list->Items[i];
            delete item;
        }

        delete list;
    }
}
//---------------------------------------------------------------------------
//use this class to protect your code
//it uses RAII principle
//
class DataGuard
{
public:
    DataGuard(TCriticalSection* cs)
        :_cs(cs)
    {
        if (_cs) _cs->Enter();
    }
    ~DataGuard()
    {
        if (_cs) _cs->Leave();
    }

private:
    TCriticalSection* _cs;
};


//---------------------------------------------------------------------------
//helper class to show hourglass cursor (in ctor) and restoring it back in dtor
//you could use it either on func start or inside any other scope
//
class BusyCursor
{
public:
    BusyCursor()
        :origCursor(Screen->Cursor)
    {
        Screen->Cursor = crHourGlass;
        Application->ProcessMessages();
    }
    ~BusyCursor()
    {
        Screen->Cursor = origCursor;
    }
private:
    Controls::TCursor origCursor;

};


//---------------------------------------------------------------------------
//helper class to pass params to main form to show some code in it's window
//
struct ShowCodeData
{
    ShowCodeData(DWORD _adr, int _idxCode, int _idxXRef, int _idxTopCode)
        :adr(_adr), idxCode(_idxCode), idxXRef(_idxXRef), idxTopCode(_idxTopCode)
        {}
    DWORD adr;
    int idxCode;
    int idxXRef;
    int idxTopCode;
};


//---------------------------------------------------------------------------
//      global API
//
// TODO: move gradually into idr manager
//---------------------------------------------------------------------------
TCriticalSection* GetSyncObj();
MDisasm& GetDisasm();

String __fastcall Guid2String(BYTE* Guid);
void __fastcall ScaleForm(TForm* AForm);
LONGLONG __fastcall Adr2Pos(ULONGLONG adr);
String __fastcall Val2Str0(DWORD Val);
String __fastcall Val2Str1(DWORD Val);
String __fastcall Val2Str2(DWORD Val);
String __fastcall Val2Str4(DWORD Val);
String __fastcall Val2Str5(DWORD Val);
String __fastcall Val2Str8(DWORD Val);
ULONGLONG __fastcall Pos2Adr(LONGLONG Pos);

void __fastcall AddClassAdr(DWORD Adr, const String& AName);
void __fastcall AddFieldXref(PFIELDINFO fInfo, DWORD ProcAdr, int ProcOfs, char type);
void __fastcall AddPicode(int Pos, BYTE Op, String Name, int Ofs);

PFIELDINFO __fastcall GetField(String TypeName, int Offset, bool* vmt, DWORD* vmtAdr);
PFIELDINFO __fastcall AddField(DWORD ProcAdr, int ProcOfs, String TypeName, BYTE Scope, int Offset, int Case, String Name, String Type);
String __fastcall MakeComment(PPICODE Picode);

bool __fastcall CanReplace(const String& fromName, const String& toName);
void __fastcall Copy2Clipboard(TStrings* items, int leftMargin, bool asmCode);

String __fastcall ExtractClassName(const String& AName);
String __fastcall ExtractProcName(const String& AName);
String __fastcall ExtractName(const String& AName);
String __fastcall ExtractType(const String& AName);
void __fastcall FillArgInfo(int k, BYTE callkind, PARGINFO argInfo, BYTE** p, int* s);
DWORD __fastcall FindClassAdrByName(const String& AName);
int __fastcall FloatNameToFloatType(String AName);

String __fastcall GetArrayElementType(String arrType);
int __fastcall GetArrayElementTypeSize(String arrType);


DWORD __fastcall GetChildAdr(DWORD Adr);
DWORD __fastcall GetClassAdr(const String& AName);
int __fastcall GetClassSize(DWORD adr);
String __fastcall GetClsName(DWORD adr);
String __fastcall GetDefaultProcName(DWORD adr);
String __fastcall GetDynaInfo(DWORD adr, WORD id, DWORD* dynAdr);
String __fastcall GetDynArrayTypeName(DWORD adr);
String __fastcall GetEnumerationString(String TypeName, Variant Val);
String __fastcall GetImmString(int Val);
String __fastcall GetImmString(String TypeName, int Val);
PInfoRec __fastcall GetInfoRec(DWORD adr);
int __fastcall GetLastLocPos(int fromAdr);
String __fastcall GetModuleVersion(const String& module);

DWORD __fastcall GetParentAdr(DWORD Adr);
String __fastcall GetParentName(DWORD adr);
String __fastcall GetParentName(const String& ClassName);
int __fastcall GetParentSize(DWORD Adr);
int __fastcall GetProcRetBytes(MProcInfo* pInfo);
int __fastcall GetProcSize(DWORD fromAdr);
//////
String __fastcall GetDecompilerRegisterName(int Idx);
String __fastcall GetSetString(String TypeName, BYTE* ValAdr);
DWORD __fastcall GetStopAt(DWORD vmtAdr);
DWORD __fastcall GetOwnTypeAdr(String AName);
PTypeRec __fastcall GetOwnTypeByName(String AName);
String __fastcall GetTypeDeref(String ATypeName);
BYTE __fastcall GetTypeKind(String AName, int* size);
//int __fastcall GetPackedTypeSize(String AName);
String __fastcall GetTypeName(DWORD TypeAdr);
int __fastcall GetTypeSize(String AName);

bool __fastcall IsBplByExport(const char* bpl);
bool __fastcall IsDefaultName(String AName);

bool __fastcall IsInheritsByAdr(const DWORD Adr1, const DWORD Adr2);
bool __fastcall IsInheritsByClassName(const String& Name1, const String& Name2);
bool __fastcall IsInheritsByProcName(const String& Name1, const String& Name2);

bool __fastcall IsSameRegister(int Idx1, int Idx2);
bool __fastcall IsValidCodeAdr(DWORD Adr);
bool __fastcall IsValidCString(int pos);
bool __fastcall IsValidImageAdr(ULONGLONG Adr);
bool __fastcall IsValidModuleName(int len, int pos);
bool __fastcall IsValidName(int len, int pos);
bool __fastcall IsValidString(int len, int pos);

void __fastcall MakeGvar(PInfoRec recN, DWORD adr, DWORD xrefAdr);
String __fastcall MakeGvarName(DWORD adr);

void __fastcall OutputDecompilerHeader(FILE* f);
int __fastcall SortUnitsByAdr(void *item1, void* item2);
int __fastcall SortUnitsByNam(void *item1, void* item2);
int __fastcall SortUnitsByOrd(void *item1, void* item2);
String __fastcall TransformString(char* str, int len);
String __fastcall TransformUString(WORD codePage, wchar_t* data, int len);
String __fastcall TrimTypeName(const String& TypeName);
String __fastcall TypeKind2Name(BYTE kind);
String __fastcall UnmangleName(String Name);

//String __fastcall InputDialogExec(String caption, String labelText, String text);
//String __fastcall ManualInput(DWORD procAdr, DWORD curAdr, String caption, String labelText);
bool __fastcall MatchCode(BYTE* code, MProcInfo* pInfo);
void __fastcall SaveCanvas(TCanvas* ACanvas);
void __fastcall RestoreCanvas(TCanvas* ACanvas);
void __fastcall DrawOneItem(String AItem, TCanvas* ACanvas, TRect &ARect, TColor AColor, int flags);


int __fastcall GetSegmentNo(DWORD Adr);
int __fastcall GetClassHeight(DWORD adr);
String __fastcall GetCommonType(String Name1, String Name2);

int __fastcall EstimateProcSize(DWORD fromAdr);
bool __fastcall StrapCheck(int pos, MProcInfo* ProcInfo);
void __fastcall StrapProc(int pos, int ProcId, MProcInfo* ProcInfo, bool useFixups, int procSize);
void __fastcall StrapVMT(int pos, int ConstId, MConstInfo* ConstInfo);
void __fastcall PropagateVMTNames(DWORD adr);
PMethodRec __fastcall GetMethodInfo(PInfoRec rec, String name);
PMethodRec __fastcall GetMethodInfo(DWORD adr, char kind, int methodOfs);

bool __fastcall IsUnitExist(String Name);
PUnitRec __fastcall GetUnit(DWORD Adr);
String __fastcall GetUnitName(PUnitRec recU);
String __fastcall GetUnitName(DWORD Adr);
void __fastcall SetUnitName(PUnitRec recU, String name);
bool __fastcall InOneUnit(DWORD Adr1, DWORD Adr2);


int __fastcall LoadIntfTable(DWORD adr, TStringList* dstList);
int __fastcall LoadAutoTable(DWORD adr, TStringList* dstList);
int __fastcall LoadFieldTable(DWORD adr, TList* dstList);
int __fastcall LoadMethodTable(DWORD adr, TList* dstList);
int __fastcall LoadMethodTable(DWORD adr, TStringList* dstList);
int __fastcall LoadDynamicTable(DWORD adr, TList* dstList);
int __fastcall LoadDynamicTable(DWORD adr, TStringList* dstList);
int __fastcall LoadVirtualTable(DWORD adr, TList* dstList);
int __fastcall LoadVirtualTable(DWORD adr, TStringList* dstList);

void __fastcall SetVmtConsts(int version);
void __fastcall AdjustVmtConsts(int Adjustment);

//Information about registry
typedef struct
{
    BYTE        result; //0 - nothing, 1 - type was set, 2 - type mismatch
    char        source; //0 - not defined; 'L' - local var; 'A' - argument; 'M' - memory; 'I' - immediate
    ULONGLONG   value;
    String      type;
} RINFO, *PRINFO;
//---------------------------------------------------------------------------

typedef struct
{
    int     id;
    char    *typname;
    char    *msgname;
} MsgInfo, *PMsgMInfo;

PMsgMInfo __fastcall GetMsgInfo(WORD msg);

//---------------------------------------------------------------------------
typedef struct
{
    char*   name;
    DWORD   impAdr;
} SysProcInfo;




//---------------------------------------------------------------------------
//Debugging/tracing tools
class MacroCall
{
public:
    MacroCall()
    {}
    void operator() (const char *szFormat, ...) const
    {
        if ( szFormat == NULL || *szFormat == 0 )
            return;

        va_list args;
        va_start(args, szFormat);

        int  bufSize;
        char szBuffer[32*1024];
        bufSize = vsnprintf(szBuffer, sizeof szBuffer, szFormat, args);
        ::OutputDebugString(szBuffer);

        va_end(args);
    }
};

#ifdef _DEBUG
#define TRACE MacroCall()
#else
#define TRACE   //do {} while(0);
#endif

//---------------------------------------------------------------------------

struct DelphiVmt
{
    DelphiVmt()
    {
        SelfPtr = 0;
        IntfTable = AutoTable = InitTable = 0;
        TypeInfo = 0;
        FieldTable = MethodTable = DynamicTable = 0;
        ClassName = 0;
        InstanceSize = 0;
        Parent = 0;
        Equals = 0;
        GetHashCode = 0;
        ToString = 0;
        SafeCallException = 0;
        AfterConstruction = 0;
        BeforeDestruction = 0;
        Dispatch = 0;
        DefaultHandler = 0;
        NewInstance = 0;
        FreeInstance = 0;
        Destroy = 0;
    }
    int SelfPtr;
    int IntfTable;
    int AutoTable;
    int InitTable;
    int TypeInfo;
    int FieldTable;
    int MethodTable;
    int DynamicTable;
    int ClassName;
    int InstanceSize;
    int Parent;
    int Equals;
    int GetHashCode;
    int ToString;
    int SafeCallException;
    int AfterConstruction;
    int BeforeDestruction;
    int Dispatch;
    int DefaultHandler;
    int NewInstance;
    int FreeInstance;
    int Destroy;

    void __fastcall SetVmtConsts(int version);
    void __fastcall AdjustVmtConsts(int Adjustment);
};


//---------------------------------------------------------------------------
//main application manager
//
//each and every module has to use its public API
//TBD: thread safety
//---------------------------------------------------------------------------

class TDfm;
class TResourceInfo;

class Idr64Manager
{
public:
    Idr64Manager();
    ~Idr64Manager();

public:
    String GetVersion() const {return IDR64Version;}

    //Project API
    void CleanProject();
    void CreateDBs(DWORD _TotalSize);

    //Flags API
    void __fastcall ClearFlag(DWORD flag, int pos);
    void __fastcall ClearFlags(DWORD flag, int pos, int num);
    bool __fastcall IsFlagSet(DWORD flag, int pos);
    bool __fastcall IsFlagEmpty(int pos);
    void __fastcall SetFlag(DWORD flag, int pos);
    void __fastcall SetFlags(DWORD flag, int pos, int num);
    void __fastcall XorFlag(DWORD Val, int pos);


    //TODO (future): hide vars into API (it is bad to have direct access to class members)
    DWORD     *Flags;     //flags for used data

    String     WrkDir;

    //lookup instructions Up/Down API
    int __fastcall GetNearestArgC(int fromPos);
    int __fastcall GetNearestDownInstruction(int fromPos);
    int __fastcall GetNearestDownInstruction(int fromPos, String Instruction);
    int __fastcall GetNearestUpPrefixFs(int fromPos);
    int __fastcall GetNearestUpInstruction(int fromPos);
    int __fastcall GetNthUpInstruction(int fromPos, int N);
    int __fastcall GetNearestUpInstruction(int fromPos, int toPos);
    int __fastcall GetNearestUpInstruction(int fromPos, int toPos, int no);
    int __fastcall GetNearestUpInstruction1(int fromPos, int toPos, String Instruction);
    int __fastcall GetNearestUpInstruction2(int fromPos, int toPos, String Instruction1, String Instruction2);
    int __fastcall BranchGetPrevInstructionType(DWORD fromAdr, DWORD* jmpAdr, PLoopInfo loopInfo);

    //Resource API
    TResourceInfo* ResInfo() const {return _ResInfo;}

    //Infos
    PInfoRec GetInfos(DWORD classAdr);
    PInfoRec GetInfosAt(int Pos);
    void SetInfosAt(int Pos, PInfoRec rec);
    bool HasInfosAt(int Pos);

    //BSS
    PInfoRec AddToBSSInfos(DWORD Adr, String AName, String ATypeName);
    void BSSInfosAddObject(String _adr, PInfoRec recN);
    int GetBSSInfosCount() const {return BSSInfos->Count;}
    PInfoRec GetBSSInfosObject(int n) const {return (PInfoRec)BSSInfos->Objects[n];}
    String GetBSSInfosString(int n) const {return BSSInfos->Strings[n];}
    //int GetBSSInfosIndexOf(const String s) const {return BSSInfos->IndexOf(s);}
    PInfoRec GetBSSInfosRec(const String s);


public:
    //Decompiler helpers
    //TODO: maybe put into Decompiler module?
    int __fastcall IsValidCode(DWORD fromAdr);
    int  __fastcall IsBoundErr(DWORD fromAdr);
    int __fastcall IsInitStackViaLoop(DWORD fromAdr, DWORD toAdr);
    bool __fastcall IsConnected(DWORD fromAdr, DWORD toAdr);
    DWORD __fastcall IsGeneralCase(DWORD fromAdr, int retAdr);
    bool __fastcall IsExit(DWORD fromAdr);
    bool __fastcall IsXorMayBeSkipped(DWORD fromAdr);

    int __fastcall IsAbs(DWORD fromAdr);
    int __fastcall IsIntOver(DWORD fromAdr);
    int __fastcall IsInlineLengthCmp(DWORD fromAdr);
    int __fastcall IsInlineLengthTest(DWORD fromAdr);
    int __fastcall IsInlineDiv(DWORD fromAdr, int* div);
    int __fastcall IsInlineMod(DWORD fromAdr, int* mod);
    int __fastcall ProcessInt64Equality(DWORD fromAdr, DWORD* maxAdr);
    int __fastcall ProcessInt64NotEquality(DWORD fromAdr, DWORD* maxAdr);
    int __fastcall ProcessInt64Comparison(DWORD fromAdr, DWORD* maxAdr);
    int __fastcall ProcessInt64ComparisonViaStack1(DWORD fromAdr, DWORD* maxAdr);
    int __fastcall ProcessInt64ComparisonViaStack2(DWORD fromAdr, DWORD* maxAdr);
    int __fastcall IsInt64Equality(DWORD fromAdr, int* skip1, int* skip2, bool *immVal, __int64* Val);
    int __fastcall IsInt64NotEquality(DWORD fromAdr, int* skip1, int* skip2, bool *immVal, __int64* Val);
    int __fastcall IsInt64Comparison(DWORD fromAdr, int* skip1, int* skip2, bool *immVal, __int64* Val);
    int __fastcall IsInt64ComparisonViaStack1(DWORD fromAdr, int* skip1, DWORD* simEnd);
    int __fastcall IsInt64ComparisonViaStack2(DWORD fromAdr, int* skip1, int* skip2, DWORD* simEnd);
    int __fastcall IsInt64Shr(DWORD fromAdr);
    int __fastcall IsInt64Shl(DWORD fromAdr);


    String __fastcall AnalyzeArguments(DWORD fromAdr);
    String __fastcall AnalyzeCall(DWORD parentAdr, int callPos, DWORD callAdr, PRINFO registers);
    DWORD  __fastcall AnalyzeProcInitial(DWORD fromAdr);
    void   __fastcall AnalyzeProc1(DWORD fromAdr, char xrefType, DWORD xrefAdr, int xrefOfs, bool maybeEmb);
    bool   __fastcall AnalyzeProc2(DWORD fromAdr, bool addArg, bool AnalyzeRetType, TList *sctx);
    void   __fastcall AnalyzeProc2(DWORD fromAdr, bool addArg, bool AnalyzeRetType);


private:
    String  IDR64Version;

    TResourceInfo* _ResInfo;   //Information about forms
    PInfoRec       *Infos;	   //Array of pointers to store items data
    TStringList    *BSSInfos;  //Data from BSS
};

//global instance (TBD: think about Singleton pattern & API like getIdr() )
extern Idr64Manager idr;

//global instance for Vmt
extern DelphiVmt Vmt;
//---------------------------------------------------------------------------
#endif
