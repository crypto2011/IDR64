//---------------------------------------------------------------------------
#ifndef DecompilerH
#define DecompilerH

#include "Infos.h"
#include "Disasm.h"

typedef struct
{
    String      name;
    DWORD       codeOfs;
    int         codeLen;
} FuncListRec, *PFuncListRec;

typedef struct UnitRec
{
    ~UnitRec(){delete names;}
    bool        trivial;        //Trivial unit
	bool		trivialIni;     //Initialization procedure is trivial
    bool        trivialFin;	    //Finalization procedure is trivial
    bool        kb;             //Unit is in knowledge base
    int			fromAdr;        //From Address
    int			toAdr;	        //To Address
    int			finadr;         //Finalization procedure address
    int         finSize;        //Finalization procedure size
    int			iniadr;         //Initialization procedure address
    int         iniSize;        //Initialization procedure size
    float       matchedPercent; //Matching procent of code in unit
    int         iniOrder;       //Initialization procs order
    TStringList *names;         //Possible names list
} UnitRec, *PUnitRec;


typedef struct
{
    int         height;
    DWORD       vmtAdr;
    String      vmtName;
} VmtListRec, *PVmtListRec;

//Delphi2
//(tkUnknown, tkInteger, tkChar, tkEnumeration, tkFloat, tkString, tkSet,
//tkClass, tkMethod, tkWChar, tkLString, tkLWString, tkVariant)


#define     ikUnknown       0x00    //UserDefined!
#define     ikInteger       0x01
#define     ikChar          0x02
#define     ikEnumeration   0x03
#define     ikFloat         0x04
#define     ikString        0x05   //ShortString
#define     ikSet           0x06
#define     ikClass         0x07
#define     ikMethod        0x08
#define     ikWChar         0x09
#define     ikLString       0x0A   //String, AnsiString
#define     ikWString       0x0B   //WideString
#define     ikVariant       0x0C
#define     ikArray         0x0D
#define     ikRecord        0x0E
#define     ikInterface     0x0F
#define     ikInt64         0x10
#define     ikDynArray      0x11
//>=2009
#define		ikUString		0x12    //UnicodeString
//>=2010
#define		ikClassRef		0x13
#define		ikPointer		0x14
#define		ikProcedure		0x15

//Дополнительные типы
#define     ikCString       0x20    //PChar, PAnsiChar
#define     ikWCString      0x21    //PWideChar

#define     ikResString     0x22
#define     ikVMT           0x23    //VMT
#define     ikGUID          0x24
#define     ikRefine        0x25    //Code, but what - procedure or function?
#define     ikConstructor   0x26
#define     ikDestructor    0x27
#define     ikProc			0x28
#define     ikFunc			0x29

#define     ikLoc           0x2A
#define     ikData          0x2B
#define     ikDataLink      0x2C    //Link to variable from other module
#define     ikExceptName    0x2D
#define     ikExceptHandler 0x2E
#define     ikExceptCase    0x2F
#define     ikSwitch        0x30
#define     ikCase          0x31
#define     ikFixup         0x32    //Fixup (for example, TlsLast)
#define     ikThreadVar     0x33
#define		ikTry			0x34	//!!!Deleted - old format!!!

typedef struct
{
    ULONGLONG   Start;
    DWORD       Size;
    DWORD       Flags;
    String      Name;
} SegmentInfo, *PSegmentInfo;

typedef struct
{
    BYTE        kind;
    DWORD       adr;
    String      name;
} TypeRec, *PTypeRec;

#define cfUndef         0x00000000
#define cfCode          0x00000001
#define cfData          0x00000002
#define cfImport        0x00000004
#define cfCall          0x00000008
#define cfProcStart     0x00000010
#define cfProcEnd		0x00000020
#define cfRTTI			0x00000040
#define cfEmbedded      0x00000080  //Calls in range of one proc (for ex. calls in FormatBuf)
#define cfPass0         0x00000100  //Initial Analyze was done
#define cfFrame         0x00000200
#define cfSwitch        0x00000400
#define cfPass1         0x00000800  //Analyze1 was done
//#define cfETable        0x00001000  //Exception Table
#define cfPush          0x00002000
#define cfDSkip         0x00004000  //For Decompiler
#define cfPop           0x00008000
#define cfSetA          0x00010000  //ecx setting
#define cfSetC          0x00020000  //edx setting
#define cfExcInfo       0x00040000  //Procedure from Exception Directory (start, end are known and contains exception processing)
#define	cfBracket		0x00080000	//Bracket (ariphmetic operation)
#define cfPass2         0x00100000  //Analyze2 was done
#define cfExport        0x00200000
#define cfPass          0x00400000  //Pass Flag (for AnalyzeArguments and Decompiler)
#define cfLoc           0x00800000  //Loc_ position
//#define cfTry           0x01000000
//#define cfFinally       0x02000000
//#define cfExcept        0x04000000
#define cfLoop          0x08000000
//#define cfFinallyExit   0x10000000  //Exit section (from try...finally construction)
#define cfVTable        0x20000000	//Flags for Interface entries (to mark start end finish of VTables)
#define cfSkip          0x40000000
#define cfInstruction   0x80000000  //Instruction begin


//---------------------------------------------------------------------------
//Precedence of operations
#define     PRECEDENCE_ATOM     8
#define     PRECEDENCE_NOT      4   //@,not
#define     PRECEDENCE_MULT     3   //*,/,div, mod,and,shl,shr,as
#define     PRECEDENCE_ADD      2   //+,-,or,xor
#define     PRECEDENCE_CMP      1   //=,<>,<,>,<=,>=,in,is
#define     PRECEDENCE_NONE     0

#define     TAB_SIZE            2

#define     IF_ARG              1
#define     IF_VAR              2
#define     IF_STACK_PTR        4
#define     IF_CALL_RESULT      8
#define     IF_VMT_ADR          16
#define     IF_CYCLE_VAR        32
#define     IF_FIELD            64
#define     IF_ARRAY_PTR        128
#define     IF_INTVAL           256
#define     IF_INTERFACE        512
#define     IF_EXTERN_VAR       1024    //User for embedded procedures
#define     IF_RECORD_FOFS      2048    //Offset inside record

#define     CF_CONSTRUCTOR      1
#define     CF_DESTRUCTOR       2
#define     CF_FINALLY          4
#define     CF_EXCEPT           8
#define     CF_LOOP             16
#define     CF_BJL              32
#define     CF_ELSE             64

#define     CMP_FAILED          0
#define     CMP_BRANCH          1
#define     CMP_SET             2

//BJL
#define     MAXSEQNUM           1024

#define     BJL_USED            -1
#define     BJL_EMPTY           0
#define	    BJL_BRANCH  		1
#define     BJL_JUMP			2
#define     BJL_LOC				3
#define     BJL_SKIP_BRANCH     4   //branches for IntOver, BoundErr,...

typedef struct
{
    char        state;          //'U' not defined; 'B' branch; 'J' jump; '@' label; 'R' return; 'S' switch
    int         bcnt;           //branches to... count
    DWORD       address;
    String      dExpr;          //condition of direct expression
    String      iExpr;          //condition of inverse expression
    String      result;
} TBJLInfo;

typedef struct
{
	bool		branch;
	bool		loc;
    int			type;
    int			address;
    int			idx;		//IDX in BJLseq
} TBJL;
//BJL

typedef struct
{
    String  L;
    char    O;
    String  R;
} CMPITEM, *PCMPITEM;

typedef struct
{
    BYTE    Precedence;
    //int     Size;       //Size in bytes
    int     Offset;     //Offset from beginning of type
    DWORD   IntValue;   //For array element size calculation
    DWORD   Flags;
    String  Value;
    String  Value1;     //For various purposes
    String  Type;
    String  Name;
} ITEM, *PITEM;

typedef struct
{
    String  Value;
    String  Name;
} WHAT, *PWHAT;

#define     itUNK   0
#define     itREG   1
#define     itLVAR  2
#define     itGVAR  3

typedef struct
{
    BYTE    IdxType;
    int     IdxValue;
    String  IdxStr;
} IDXINFO, *PIDXINFO;

class TForInfo
{
public:
    bool    NoVar;
    bool    Down;       //downto (=true)
    int     StopAdr;    //instructions are ignored from this address and to end of cycle
    String  From;
    String  To;
    IDXINFO VarInfo;
    IDXINFO CntInfo;
public:
    __fastcall TForInfo(bool ANoVar, bool ADown, int AStopAdr, String AFrom, String ATo, BYTE AVarType, int AVarIdx, BYTE ACntType, int ACntIdx);
};

typedef  TForInfo *PForInfo;

class TWhileInfo
{
public:
    bool    NoCondition;    //No condition
public:
    __fastcall TWhileInfo(bool ANoCond);
};

typedef TWhileInfo *PWhileInfo;

class TLoopInfo
{
public:
    BYTE        Kind;       //'F'- for; 'W' - while; 'T' - while true; 'R' - repeat
    DWORD       ContAdr;    //Continue address
    DWORD       BreakAdr;   //Break address
    DWORD       LastAdr;    //Last address for decompilation (skip some last instructions)
    PForInfo    forInfo;
    PWhileInfo  whileInfo;
public:
    __fastcall TLoopInfo(BYTE AKind, DWORD AContAdr, DWORD ABreakAdr, DWORD ALastAdr);
    __fastcall ~TLoopInfo();
};

typedef TLoopInfo *PLoopInfo;

//cmpStack Format: "XYYYYYYY^ZZZZ" (== YYYYYY X ZZZZ)
//'A'-JO;'B'-JNO;'C'-JB;'D'-'JNB';'E'-JZ;'F'-JNZ;'G'-JBE;'H'-JA;
//'I'-'JS';'J'-JNS;'K'-JP;'L'-JNP;'M'-JL;'N'-JGE;'O'-JLE;'P'-JG

//Only registers eax, ecx, edx, ebx, esp, ebp, esi, edi 
typedef ITEM REGS[8];

class TNamer
{
public:
    int             MaxIdx;
    TStringList     *Names;
    __fastcall TNamer();
    __fastcall ~TNamer();
    String __fastcall MakeName(String shablon);
};

struct TCaseTreeNode;
struct TCaseTreeNode
{
    TCaseTreeNode   *LNode;
    TCaseTreeNode   *RNode;
    DWORD           ZProc;
    int             FromVal;
    int             ToVal;
};

//structure for saving context of all registers
typedef struct
{
    DWORD   adr;
    REGS    gregs;  //general registers
    REGS    fregs;  //float point registers
} DCONTEXT, *PDCONTEXT;

class TDecompiler;

#define REGNUM 130

class TDecompileEnv
{
public:
    String      ProcName;       //Name of decompiled procedure
    DWORD       StartAdr;       //Start of decompilation area
    int         Size;           //Size of decompilation area
    int         Indent;         //For output source code
    bool        Alarm;
    bool        BpBased;
    int         LocBase;
    DWORD       StackSize;
    PITEM       Stack;
    DWORD       ErrAdr;
    String      LastResString;
    TStringList *Body;
    ITEM        RegInfo[REGNUM];
    ITEM        FStack[8];      //Floating registers stack
    TNamer      *Namer;
    int         BJLnum;
    int         BJLmaxbcnt;
    TList       *SavedContext;
    TList       *BJLseq;//TBJLInfo
    TList       *bjllist;//TBJL
    TList       *CmpStack;
    bool        Embedded;       //Is proc embedded
    TStringList *EmbeddedList;  //List of embedded procedures addresses

    __fastcall TDecompileEnv(DWORD AStartAdr, int ASize, PInfoRec recN);
    __fastcall ~TDecompileEnv();
    String __fastcall GetFieldName(PFIELDINFO fInfo);
    String __fastcall GetArgName(PARGINFO argInfo);
    String __fastcall GetGvarName(DWORD adr);
    String __fastcall GetLvarName(int Ofs, String Type);
    void __fastcall AssignItem(PITEM DstItem, PITEM SrcItem);
    void __fastcall AddToBody(String src);
    void __fastcall AddToBody(TStringList* src);
    bool __fastcall IsExitAtBodyEnd();

    void __fastcall OutputSourceCodeLine(String line);
    void __fastcall OutputSourceCode();
    void __fastcall MakePrototype();
    void __fastcall DecompileProc();
    //BJL
    bool __fastcall GetBJLRange(DWORD fromAdr, DWORD* bodyBegAdr, DWORD* bodyEndAdr, DWORD* jmpAdr, PLoopInfo loopInfo);
    void __fastcall CreateBJLSequence(DWORD fromAdr, DWORD bodyBegAdr, DWORD bodyEndAdr);
    void __fastcall UpdateBJLList();
    void __fastcall BJLAnalyze();
    bool __fastcall BJLGetIdx(int* idx, int from, int num);
    bool __fastcall BJLCheckPattern1(char* t, int from);
    bool __fastcall BJLCheckPattern2(char* t, int from);
    int __fastcall BJLFindLabel(int address, int* no);
    void __fastcall BJLSeqSetStateU(int* idx, int num);
    void __fastcall BJLListSetUsed(int from, int num);
    char __fastcall ExprGetOperation(String s);
    void __fastcall ExprMerge(String& dst, String src, char op);//dst = dst op src, op = '|' or '&'
    String __fastcall PrintBJL();
    PDCONTEXT __fastcall GetContext(DWORD Adr);
    void __fastcall SaveContext(DWORD Adr);
    void __fastcall RestoreContext(DWORD Adr);
};

class TDecompiler
{
public:
    bool            WasRet;     //Was ret instruction
    char            CmpOp;      //Compare operation
    DWORD           CmpAdr;     //Compare dest address
    int             _ESP_;      //Stack pointer
    int             _TOP_;      //Top of FStack
    DISINFO         DisInfo;
    CMPITEM         CmpInfo;
    TDecompileEnv   *Env;
    BYTE            *DeFlags;
    PITEM           Stack;

    __fastcall TDecompiler(TDecompileEnv* AEnv);
    __fastcall ~TDecompiler();
    bool __fastcall CheckPrototype(PInfoRec ARec);
    void __fastcall ClearStop(DWORD Adr);
    DWORD __fastcall Decompile(DWORD fromAdr, DWORD flags, PLoopInfo loopInfo);
    DWORD __fastcall DecompileCaseEnum(DWORD fromAdr, int N, PLoopInfo loopInfo);
    DWORD __fastcall DecompileGeneralCase(DWORD fromAdr, DWORD markAdr, PLoopInfo loopInfo, int N);
    PITEM __fastcall FGet(int idx);
    PITEM __fastcall FPop();
    void __fastcall FPush(PITEM val);
    void __fastcall FSet(int idx, PITEM val);
    void __fastcall FXch(int idx1, int idx2);
    PFIELDINFO __fastcall GetArrayFieldOffset(String ATypeName, int AFromOfs, int AScale);
    int __fastcall GetCmpInfo(DWORD fromAdr);
    String __fastcall GetCycleFrom();
    void __fastcall GetCycleIdx(PIDXINFO IdxInfo, DISINFO* ADisInfo);
    String __fastcall GetCycleTo();
    void __fastcall GetFloatItemFromStack(int Esp, PITEM Dst, int FloatType);
    String __fastcall GetStringArgument(PITEM item);
    PLoopInfo __fastcall GetLoopInfo(int fromAdr);
    void __fastcall GetMemItem(int CurAdr, PITEM Dst, BYTE Op);
    void __fastcall GetRegItem(int Idx, PITEM Dst);
    String __fastcall GetRegType(int Idx);
    String __fastcall GetSysCallAlias(String AName);
    bool __fastcall Init(DWORD fromAdr);
    void __fastcall InitFlags();
    void __fastcall MarkCaseEnum(DWORD fromAdr);
    void __fastcall MarkGeneralCase(DWORD fromAdr);
    PITEM __fastcall Pop();
    void __fastcall Push(PITEM item);
    void __fastcall SetStackPointers(TDecompiler* ASrc);
    void __fastcall SetDeFlags(BYTE* ASrc);
    void __fastcall SetRegItem(int Idx, PITEM Val);
    void __fastcall SetStop(DWORD Adr);
    bool __fastcall SimulateCall(DWORD curAdr, DWORD callAdr, int instrLen, PMethodRec recM, DWORD AClassAdr);
    void __fastcall SimulateFloatInstruction(DWORD curAdr, int instrLen);
    void __fastcall SimulateFormatCall();
    void __fastcall SimulateInherited(DWORD procAdr);
    void __fastcall SimulateInstr1(DWORD curAdr, BYTE Op);
    void __fastcall SimulateInstr2(DWORD curAdr, BYTE Op);
    void __fastcall SimulateInstr2RegImm(DWORD curAdr, BYTE Op);
    void __fastcall SimulateInstr2RegMem(DWORD curAdr, BYTE Op);
    void __fastcall SimulateInstr2RegReg(DWORD curAdr, BYTE Op);
    void __fastcall SimulateInstr2MemImm(DWORD curAdr, BYTE Op);
    void __fastcall SimulateInstr2MemReg(DWORD curAdr, BYTE Op);
    void __fastcall SimulateInstr3(DWORD curAdr, BYTE Op);
    void __fastcall SimulatePop(DWORD curAdr);
    void __fastcall SimulatePush(DWORD curAdr, bool bShowComment);
    bool __fastcall SimulateSysCall(String name, DWORD procAdr, int instrLen);
    int __fastcall AnalyzeConditions(int brType, DWORD curAdr, DWORD sAdr, DWORD jAdr, PLoopInfo loopInfo);

private:
    int    __fastcall GetRecordSize(String AName);
    String __fastcall GetRecordFields(int AOfs, String AType);
    int    __fastcall GetArraySize(String arrType);
    bool   __fastcall GetArrayIndexes(String arrType, int ADim, int* LowIdx, int* HighIdx);

};
//---------------------------------------------------------------------------
#endif
