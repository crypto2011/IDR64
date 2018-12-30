//---------------------------------------------------------------------------
#include <vcl.h>
#pragma hdrstop

#include "Threads.h"
#include "Misc.h"
#include "TypeInfo.h"

extern  BYTE        *Code;
//extern  PInfoRec    *Infos;

//extern  int         VmtSelfPtr;
//extern  int         VmtIntfTable;
//extern  int         VmtAutoTable;
//extern  int         VmtInitTable;
//extern  int         VmtTypeInfo;
//extern  int         VmtFieldTable;
//extern  int         VmtMethodTable;
//extern  int         VmtDynamicTable;
//extern  int         VmtClassName;
//extern  int         VmtInstanceSize;
//extern  int         VmtParent;
//extern  int         VmtEquals;
//extern  int         VmtGetHashCode;
//extern  int         VmtToString;
//extern  int         VmtSafeCallException;
//extern  int         VmtAfterConstruction;
//extern  int         VmtBeforeDestruction;
//extern  int         VmtDispatch;
//extern  int         VmtDefaultHandler;
//extern  int         VmtNewInstance;
//extern  int         VmtFreeInstance;
//extern  int         VmtDestroy;

//extern MDisasm        Disasm;
extern MKnowledgeBase KnowledgeBase;
//---------------------------------------------------------------------------
//IntfTable присутствует, если класс порожден от интерфейсов
/*
Interfaces
    Any class can implement any number of interfaces. The compiler stores a
    table of interfaces as part of the class's RTTI. The VMT points to the table
    of interfaces, which starts with a 4-byte count, followed by a list of
    interface records. Each interface record contains the GUID, a pointer to the
    interface's VMT, the offset to the interface's hidden field, and a pointer
    to a property that implements the interface with the implements directive.
    If the offset is zero, the interface property (called ImplGetter) must be
    non-nil, and if the offset is not zero, ImplGetter must be nil. The interface
    property can be a reference to a field, a virtual method, or a static method,
    following the conventions of a property reader (which is described earlier
    in this chapter, under Section 3.2.3"). When an object is constructed, Delphi
    automatically checks all the interfaces, and for each interface with a
    non-zero IOffset, the field at that offset is set to the interface's VTable
    (a pointer to its VMT). Delphi defines the the types for the interface table,
    unlike the other RTTI tables, in the System unit. These types are shown in
    Example 3.9.
    Example 3.9. Type Declarations for the Interface Table

    type
      PInterfaceEntry = ^TInterfaceEntry;
      TInterfaceEntry = record
        IID: TGUID;
        VTable: Pointer;
        IOffset: Integer;
        ImplGetter: Integer;
      end;

      PInterfaceTable = ^TInterfaceTable;
      TInterfaceTable = record
        EntryCount: Integer;
        // Declare the type with the largest possible size,
        // but the true size of the array is EntryCount elements.
        Entries: array[0..9999] of TInterfaceEntry;
        Intfs:array[0..EntryCount - 1] of PPTypeInfo;
      end;

    TObject implements several methods for accessing the interface table.
*/
void __fastcall TAnalyzeThread::ScanIntfTable(DWORD adr)
{
    bool        vmtProc;
    WORD        _dx, _bx, _si;
    int         n, pos, entryCount, cnt, vmtOfs, vpos, _pos, iOffset;
    DWORD       vmtAdr, intfAdr, vAdr, iAdr, _adr;
    String      className, name;
    PInfoRec    recN, recN1;
    PMethodRec  recM;
    BYTE        GUID[16];

    if (!IsValidImageAdr(adr)) return;

    className = GetClsName(adr);
    recN = GetInfoRec(adr);
    vmtAdr = adr - Vmt.SelfPtr;
    pos = Adr2Pos(vmtAdr) + Vmt.IntfTable;
    intfAdr = *((DWORD*)(Code + pos));
    if (!intfAdr) return;

    pos = Adr2Pos(intfAdr);
    entryCount = *((ULONGLONG*)(Code + pos)); pos += 8;

    for (n = 0; n < entryCount; n++)
    {
        memmove(GUID, Code + pos, 16); pos += 16;
        //VTable
        vAdr = *((ULONGLONG*)(Code + pos)); pos += 8;
        if (IsValidCodeAdr(vAdr))
        {
            cnt = 0;
            vpos = Adr2Pos(vAdr);
            for (int v = 0;;v++)
            {
                if (idr.IsFlagSet(cfVTable, vpos)) cnt++;
                if (cnt == 2) break;
                iAdr = *((ULONGLONG*)(Code + vpos)); _adr = iAdr;
                _pos = Adr2Pos(_adr); DISINFO disInfo;
                vmtProc = false; vmtOfs = 0;
                _dx = 0; _bx = 0; _si = 0;
                while (1)
                {
                    int instrlen = GetDisasm().Disassemble(Code + _pos, (__int64)_adr, &disInfo, 0);
                    if ((disInfo.OpType[0] == otMEM || disInfo.OpType[1] == otMEM) &&
                        disInfo.BaseReg != 20)//to exclude instruction "xchg reg, [esp]"
                    {
                        vmtOfs = disInfo.Offset;
                    }
                    if (disInfo.OpType[0] == otREG && disInfo.OpType[1] == otIMM)
                    {
                        if (disInfo.OpRegIdx[0] == 10)//dx
                            _dx = disInfo.Immediate;
                        else if (disInfo.OpRegIdx[0] == 11)//bx
                            _bx = disInfo.Immediate;
                        else if (disInfo.OpRegIdx[0] == 14)//si
                            _si = disInfo.Immediate;
                    }
                    if (disInfo.Call)
                    {
                        recN1 = GetInfoRec(disInfo.Immediate);
                        if (recN1)
                        {
                            if (recN1->SameName("@CallDynaInst") ||
                                recN1->SameName("@CallDynaClass"))
                            {
                                GetDynaInfo(adr, _si, &iAdr);
                                break;
                            }
                            else if (recN1->SameName("@FindDynaInst") ||
                                     recN1->SameName("@FindDynaClass"))
                            {
                                GetDynaInfo(adr, _dx, &iAdr);
                                break;
                            }
                        }
                    }
                    if (disInfo.Branch && !disInfo.Conditional)
                    {
                        if (IsValidImageAdr(disInfo.Immediate))
                            iAdr = disInfo.Immediate;
                        else
                            vmtProc = true;
                        break;
                    }
                    else if (disInfo.Ret)
                    {
                        vmtProc = true;
                        break;
                    }
                    _pos += instrlen; _adr += instrlen;
                }
                if (!vmtProc && IsValidImageAdr(iAdr))
                {
                    idr.AnalyzeProcInitial(iAdr);
                    recN1 = GetInfoRec(iAdr);
                    if (recN1)
                    {
                        if (recN1->HasName())
                        {
                            className = ExtractClassName(recN1->GetName());
                            name = ExtractProcName(recN1->GetName());
                        }
                        else
                            name = GetDefaultProcName(iAdr);
                        if (v >= 3)
                        {
                            if (!recN1->HasName()) recN1->SetName(className + "." + name);
                        }
                    }
                }
                vpos += 8;
            }
        }
        //iOffset
        iOffset = *((LONGLONG*)(Code + pos)); pos += 8;
        //ImplGetter
        pos += 8;
        recN->vmtInfo->AddInterface(Val2Str8(vAdr) + " " + Val2Str4(iOffset) + " " + Guid2String(GUID));
    }
}
//---------------------------------------------------------------------------
/*
Automated Methods
    The automated section of a class declaration is now obsolete because it is
    easier to create a COM automation server with Delphi's type library editor,
    using interfaces. Nonetheless, the compiler currently supports automated
    declarations for backward compatibility. A future version of the compiler
    might drop support for automated declarations.
    The OleAuto unit tells you the details of the automated method table: The
    table starts with a 2-byte count, followed by a list of automation records.
    Each record has a 4-byte dispid (dispatch identifier), a pointer to a short
    string method name, 4-bytes of flags, a pointer to a list of parameters,
    and a code pointer. The parameter list starts with a 1-byte return type,
    followed by a 1-byte count of parameters, and ends with a list of 1-byte
    parameter types. The parameter names are not stored. Example 3.8 shows the
    declarations for the automated method table.
    Example 3.8. The Layout of the Automated Method Table

    const
      { Parameter type masks }
      atTypeMask = $7F;
      varStrArg  = $48;
      atByRef    = $80;
      MaxAutoEntries = 4095;
      MaxAutoParams = 255;

    type
      TVmtAutoType = Byte;
      { Automation entry parameter list }
      PAutoParamList = ^TAutoParamList;
      TAutoParamList = packed record
        ReturnType: TVmtAutoType;
        Count: Byte;
        Types: array[1..Count] of TVmtAutoType;
      end;
      { Automation table entry }
      PAutoEntry = ^TAutoEntry;
      TAutoEntry = packed record
        DispID: LongInt;
        Name: PShortString;
        Flags: LongInt; { Lower byte contains flags }
        Params: PAutoParamList;
        Address: Pointer;
      end;

      { Automation table layout }
      PAutoTable = ^TAutoTable;
      TAutoTable = packed record
        Count: LongInt;
        Entries: array[1..Count] of TAutoEntry; 
      end;
*/

//Auto function prototype can be recovered from AutoTable!!!
void __fastcall TAnalyzeThread::ScanAutoTable(DWORD Adr)
{
    if (!IsValidImageAdr(Adr)) return;

    DWORD vmtAdr = Adr - Vmt.SelfPtr;
    DWORD pos = Adr2Pos(vmtAdr) + Vmt.AutoTable;
    DWORD autoAdr = *((DWORD*)(Code + pos));
    if (!autoAdr) return;

    String className = GetClsName(Adr);
    PInfoRec recN = GetInfoRec(Adr);

    pos = Adr2Pos(autoAdr);
    int entryCount = *((int*)(Code + pos)); pos += 4;

    for (int i = 0; i < entryCount; i++)
    {
        int dispID = *((int*)(Code + pos)); pos += 4;

        DWORD nameAdr = *((ULONGLONG*)(Code + pos)); pos += 8;
        DWORD posn = Adr2Pos(nameAdr);
        BYTE len = *(Code + posn); posn++;
        String name = String((char*)(Code + posn), len);
        String procname = className + ".";

        int flags = *((int*)(Code + pos)); pos += 4;
        DWORD params = *((ULONGLONG*)(Code + pos)); pos += 8;
        DWORD address = *((ULONGLONG*)(Code + pos)); pos += 8;
        
        //afVirtual
        if ((flags & 8) == 0)
        {
            //afPropGet
            if (flags & 2) procname += "Get";
            //afPropSet
            if (flags & 4) procname += "Set";
        }
        else
        {
            //virtual table function
            address = *((DWORD*)(Code + Adr2Pos(vmtAdr + address)));
        }

        procname += name;
        idr.AnalyzeProcInitial(address);
        PInfoRec recN1 = GetInfoRec(address);
        if (!recN1) recN1 = new InfoRec(Adr2Pos(address), ikRefine);
        if (!recN1->HasName()) recN1->SetName(procname);
        //Method
        if ((flags & 1) != 0) recN1->procInfo->flags |= PF_METHOD;
        //params
        int ppos = Adr2Pos(params);
        BYTE typeCode = *(Code + ppos); ppos++;
        BYTE paramsNum = *(Code + ppos); ppos++;
        for (int m = 0; m < paramsNum; m++)
        {
            BYTE argType = *(Code + ppos); ppos++;

        }
        recN->vmtInfo->AddMethod(false, 'A', dispID, address, procname);
    }
}
//---------------------------------------------------------------------------
/*
Initialization and Finalization
    When Delphi constructs an object, it automatically initializes strings,
    dynamic arrays, interfaces, and Variants. When the object is destroyed,
    Delphi must decrement the reference counts for strings, interfaces, dynamic
    arrays, and free Variants and wide strings. To keep track of this information,
    Delphi uses initialization records as part of a class's RTTI. In fact, every
    record and array that requires finalization has an associated initialization
    record, but the compiler hides these records. The only ones you have access
    to are those associated with an object's fields.
    A VMT points to an initialization table. The table contains a list of
    initialization records. Because arrays and records can be nested, each
    initialization record contains a pointer to another initialization table,
    which can contain initialization records, and so on. An initialization table
    uses a TTypeKind field to keep track of whether it is initializing a string,
    a record, an array, etc.
    An initialization table begins with the type kind (1 byte), followed by the
    type name as a short string, a 4-byte size of the data being initialized, a
    4-byte count for initialization records, and then an array of zero or more
    initialization records. An initialization record is just a pointer to a
    nested initialization table, followed by a 4-byte offset for the field that
    must be initialized. Example 3.7 shows the logical layout of the initialization
    table and record, but the declarations depict the logical layout without
    being true Pascal code.
    Example 3.7. The Layout of the Initialization Table and Record

    type
      { Initialization/finalization record }
      PInitTable = ^TInitTable;
      TInitRecord = packed record
        InitTable: ^PInitTable;
        Offset: LongWord;        // Offset of field in object
      end;
      { Initialization/finalization table }
      TInitTable = packed record
      {$MinEnumSize 1} // Ensure that TypeKind takes up 1 byte.
        TypeKind: TTypeKind;
        TypeName: packed ShortString;
        DataSize: LongWord;
        Count: LongWord;
        // If TypeKind=ikArray, Count is the array size, but InitRecords
        // has only one element; if the type kind is tkRecord, Count is the
        // number of record members, and InitRecords[] has a
        // record for each member. For all other types, Count=0.
        InitRecords: array[1..Count] of TInitRecord;
      end;
*/

void __fastcall TAnalyzeThread::ScanInitTable(DWORD Adr)
{
    if (!IsValidImageAdr(Adr)) return;

    PInfoRec recN = GetInfoRec(Adr);
    DWORD vmtAdr = Adr - Vmt.SelfPtr;
    DWORD pos = Adr2Pos(vmtAdr) + Vmt.InitTable;
    DWORD initAdr = *((DWORD*)(Code + pos));
    if (!initAdr) return;

    pos = Adr2Pos(initAdr);
    pos++;  	//skip 0xE
    pos++;    	//unknown
    pos += 4;	//unknown
    DWORD num = *((DWORD*)(Code + pos)); pos += 4;

    for (int i = 0; i < num; i++)
    {
        DWORD typeAdr = *((ULONGLONG*)(Code + pos)); pos += 8;
        DWORD post = Adr2Pos(typeAdr);
        post += 8;  //skip SelfPtr
        post++;     //skip tkKind
        BYTE len = *(Code + post); post++;
        String typeName = String((char*)&Code[post], len);
        int fieldOfs = *((LONGLONG*)(Code + pos)); pos += 8;
        recN->vmtInfo->AddField(0, 0, FIELD_PUBLIC, fieldOfs, -1, "", typeName);
    }
}

//---------------------------------------------------------------------------
//For Version>=2010
//Count: Word; // Published fields
//ClassTab: PVmtFieldClassTab
//Entry: array[1..Count] of TVmtFieldEntry
//ExCount: Word;
//ExEntry: array[1..ExCount] of TVmtFieldExEntry;
//================================================
//TVmtFieldEntry
//FieldOffset: Longword;
//TypeIndex: Word; // index into ClassTab
//Name: ShortString;
//================================================
//TFieldExEntry = packed record
//Flags: Byte;
//TypeRef: PPTypeInfo;
//Offset: Longword;
//Name: ShortString;
//AttrData: TAttrData
void __fastcall TAnalyzeThread::ScanFieldTable(DWORD Adr)
{
    if (!IsValidImageAdr(Adr)) return;

    PInfoRec recN = GetInfoRec(Adr);
    DWORD vmtAdr = Adr - Vmt.SelfPtr;
    DWORD pos = Adr2Pos(vmtAdr) + Vmt.FieldTable;
    DWORD fieldAdr = *((DWORD*)(Code + pos));
    if (!fieldAdr) return;

    pos = Adr2Pos(fieldAdr);
    WORD count = *((WORD*)(Code + pos)); pos += 2;
    DWORD typesTab = *((ULONGLONG*)(Code + pos)); pos += 8;

    for (int i = 0; i < count; i++)
    {
        int fieldOfs = *((int*)(Code + pos)); pos += 4;
        WORD idx = *((WORD*)(Code + pos)); pos += 2;
        BYTE len = Code[pos]; pos++;
        String name = String((char*)(Code + pos), len); pos += len;

        DWORD post = Adr2Pos(typesTab) + 2 + 8 * idx;
        DWORD classAdr = *((ULONGLONG*)(Code + post));
        if (idr.IsFlagSet(cfImport, Adr2Pos(classAdr)))
        {
            PInfoRec recN1 = GetInfoRec(classAdr);
            recN->vmtInfo->AddField(0, 0, FIELD_PUBLISHED, fieldOfs, -1, name, recN1->GetName());
        }
        else
        {
            recN->vmtInfo->AddField(0, 0, FIELD_PUBLISHED, fieldOfs, -1, name, GetClsName(classAdr));
        }
    }
    WORD exCount = *((WORD*)(Code + pos)); pos += 2;
    for (int i = 0; i < exCount; i++)
    {
        BYTE flags = Code[pos]; pos++;
        DWORD typeRef = *((ULONGLONG*)(Code + pos)); pos += 8;
        int offset = *((int*)(Code + pos)); pos += 4;
        BYTE len = Code[pos]; pos++;
        String name = String((char*)(Code + pos), len); pos += len;
        WORD dw = *((WORD*)(Code + pos)); pos += dw;
        recN->vmtInfo->AddField(0, 0, FIELD_PUBLISHED, offset, -1, name, GetTypeName(typeRef));
    }
}
//---------------------------------------------------------------------------
//{ vmtMethodTable entry in VMT }
//TVmtMethodTable = packed record
//  Count: Word;
//  {Entry: array[1..Count] of TVmtMethodEntry;}
//  {ExCount: Word;}
//  {ExEntry: array[1..ExCount] of TVmtMethodExEntry;}
//  {VirtCount: Word;}
//TVmtMethodEntry = packed record
//  Len: Word;
//  CodeAddress: Pointer;
//  Name: ShortString;
//  {Tail: TVmtMethodEntryTail;} // only exists if Len indicates data here
//TVmtMethodEntryTail = packed record
//  Version: Byte; // =3
//  CC: TCallConv;
//  ResultType: PPTypeInfo; // nil for procedures
//  ParOff: Word; // total size of data needed for stack parameters + 8 (ret-addr + pushed EBP)
//  ParamCount: Byte;
//  {Params: array[1..ParamCount] of TVmtMethodParam;
//  AttrData: TAttrData;}
//TVmtMethodExEntry = packed record
//  Entry: PVmtMethodEntry;
//  Flags: Word;
//  VirtualIndex: Smallint; // signed word
//TVmtMethodParam = packed record
//  Flags: Byte;
//  ParamType: PPTypeInfo;
//  ParOff: Byte; // Parameter location: 0..2 for reg, >=8 for stack
//  Name: ShortStringBase;
//  {AttrData: TAttrData;}

void __fastcall TAnalyzeThread::ScanMethodTable(DWORD adr, String className)
{
    BYTE        len;
    WORD        skipNext;
    DWORD       codeAdr;
    int         spos, pos;
    String      name, methodName;

    if (!IsValidImageAdr(adr)) return;

    DWORD vmtAdr = adr - Vmt.SelfPtr;
    DWORD methodAdr = *((DWORD*)(Code + Adr2Pos(vmtAdr) + Vmt.MethodTable));
    if (!methodAdr) return;

    pos = Adr2Pos(methodAdr);
    WORD count = *((WORD*)(Code + pos)); pos += 2;
    for (int n = 0; n < count; n++)
    {
        spos = pos;
    	skipNext = *((WORD*)(Code + pos)); pos += 2;    //Len
        codeAdr = *((ULONGLONG*)(Code + pos)); pos += 8;    //CodeAddress
        len = Code[pos]; pos++;
        name = String((char*)&Code[pos], len); pos += len;  //Name

        //as added   why this code was removed? 
        methodName = className + "." + name;
        DWORD pos1 = Adr2Pos(codeAdr);
        PInfoRec recN1 = GetInfoRec(codeAdr);
        if (!recN1)
        {
            recN1 = new InfoRec(pos1, ikRefine);
            recN1->SetName(methodName);
        }        
        //~

        idr.GetInfosAt(Adr2Pos(adr))->vmtInfo->AddMethod(false, 'M', -1, codeAdr, methodName);
        pos = spos + skipNext;
    }
    WORD exCount = *((WORD*)(Code + pos)); pos += 2;
    for (int n = 0; n < exCount; n++)
    {
        //Entry
        DWORD entry = *((ULONGLONG*)(Code + pos)); pos += 8;
        //Flags
        pos += 2;
        //VirtualIndex
        pos += 2;
        spos = pos;
        //Entry
        pos = Adr2Pos(entry);
        skipNext = *((WORD*)(Code + pos)); pos += 2;
        codeAdr = *((ULONGLONG*)(Code + pos)); pos += 8;
        len = Code[pos]; pos++;
        name = String((char*)&Code[pos], len); pos += len;
        idr.GetInfosAt(Adr2Pos(adr))->vmtInfo->AddMethod(false, 'M', -1, codeAdr, className + "." + name);
        pos = spos;
    }
}

//---------------------------------------------------------------------------
void __fastcall TAnalyzeThread::ScanDynamicTable(DWORD adr)
{
    PInfoRec    recN, recN1, recN2;

    if (!IsValidImageAdr(adr)) return;

    recN = GetInfoRec(adr);

    if (!recN) return;

    DWORD vmtAdr = adr - Vmt.SelfPtr;
    DWORD pos = Adr2Pos(vmtAdr) + Vmt.DynamicTable;
    DWORD dynamicAdr = *((DWORD*)(Code + pos));
    if (!dynamicAdr) return;

    String className = GetClsName(adr);

    pos = Adr2Pos(dynamicAdr);
    WORD num = *((WORD*)(Code + pos)); pos += 2;
    DWORD post = pos + 2 * num;
    //First fill wellknown names
    for (int i = 0; i < num; i++)
    {
        WORD msg = *((WORD*)(Code + pos)); pos += 2;
        DWORD procAdr = *((ULONGLONG*)(Code + post)); post += 8;
    	MethodRec recM;
        recM.abstract = false;
        recM.kind = 'D';
        recM.id = (int)msg;
        recM.address = procAdr;
        recM.name = "";

        recN1 = GetInfoRec(procAdr);
        if (recN1 && recN1->HasName())
            recM.name = recN1->GetName();
        else
        {
            PMsgMInfo _info = GetMsgInfo(msg);
            if (_info)
            {
                String typname = _info->typname;
                if (typname != "")
                {
                    if (!recN1) recN1 = new InfoRec(Adr2Pos(procAdr), ikRefine);
                    recM.name = className + "." + typname;
                    recN1->SetName(recM.name);
                }
            }
            if (recM.name == "")
            {
                DWORD parentAdr = GetParentAdr(adr);
                while (parentAdr)
                {
                    recN2 = GetInfoRec(parentAdr);
                    if (recN2)
                    {
                        DWORD vmtAdr1 = parentAdr - Vmt.SelfPtr;
                        DWORD pos1 = Adr2Pos(vmtAdr1) + Vmt.DynamicTable;
                        dynamicAdr = *((DWORD*)(Code + pos1));
                        if (dynamicAdr)
                        {
                            pos1 = Adr2Pos(dynamicAdr);
                            WORD num1 = *((WORD*)(Code + pos1)); pos1 += 2;
                            DWORD post1 = pos1 + 2 * num1;

                            for (int j = 0; j < num1; j++)
                            {
                                WORD msg1 = *((WORD*)(Code + pos1)); pos1 += 2;
                                DWORD procAdr1 = *((ULONGLONG*)(Code + post1)); post1 += 8;
                                if (msg1 == msg)
                                {
                                    recN2 = GetInfoRec(procAdr1);
                                    if (recN2 && recN2->HasName())
                                    {
                                        int dpos = recN2->GetName().Pos(".");
                                        if (dpos)
                                            recM.name = className + recN2->GetName().SubString(dpos, recN2->GetNameLength() - dpos + 1);
                                        else
                                            recM.name = recN2->GetName();
                                    }
                                    break;
                                }
                            }
                            if (recM.name != "") break;
                        }
                    }
                    parentAdr = GetParentAdr(parentAdr);
                }
            }

            if (recM.name == "" || SameText(recM.name, "@AbstractError"))
            	recM.name = className + ".sub_" + Val2Str8(recM.address);

            recN1 = new InfoRec(Adr2Pos(procAdr), ikRefine);
            recN1->SetName(recM.name);
        }
        recN->vmtInfo->AddMethod(recM.abstract, recM.kind, recM.id, recM.address, recM.name);
    }
}
//---------------------------------------------------------------------------
//Create recN->methods list
void __fastcall TAnalyzeThread::ScanVirtualTable(DWORD adr)
{
    int         m, pos, idx;
    DWORD       vmtAdr, stopAt;
    String      clsName;
    PInfoRec    recN, recN1;
    MethodRec   recM;
    MProcInfo   aInfo;
    MProcInfo*  pInfo = &aInfo;

    if (!IsValidImageAdr(adr)) return;
    clsName = GetClsName(adr);
    vmtAdr = adr - Vmt.SelfPtr;
    stopAt = GetStopAt(vmtAdr);
    if (vmtAdr == stopAt) return;

    pos = Adr2Pos(vmtAdr) + Vmt.Parent + 8;
    recN = GetInfoRec(vmtAdr + Vmt.SelfPtr);

    for (m = Vmt.Parent + 8;; m += 8, pos += 8)
    {
        if (Pos2Adr(pos) == stopAt) break;

        recM.abstract = false;
        recM.address = *((DWORD*)(Code + pos));

        recN1 = GetInfoRec(recM.address);
        if (recN1 && recN1->HasName())
        {
            if (recN1->HasName())
            {
                if (!recN1->SameName("@AbstractError"))
                {
                    recM.name = recN1->GetName();
                }
                else
                {
                    recM.abstract = true;
                    recM.name = "";
                }
            }
        }
        else
        {
            recM.name = "";
            if (m == Vmt.FreeInstance)
                recM.name = clsName + "." + "FreeInstance";
            else if (m == Vmt.NewInstance)
                recM.name = clsName + "." + "NewInstance";
            else if (m == Vmt.DefaultHandler)
                recM.name = clsName + "." + "DefaultHandler";
            if (m == Vmt.SafeCallException)
                recM.name = clsName + "." + "SafeCallException";
            else if (m == Vmt.AfterConstruction)
                recM.name = clsName + "." + "AfterConstruction";
            else if (m == Vmt.BeforeDestruction)
                recM.name = clsName + "." + "BeforeDestruction";
            else if (m == Vmt.Dispatch)
                recM.name = clsName + "." + "Dispatch";
            if (m == Vmt.Equals)
                recM.name = clsName + "." + "Equals";
            else if (m == Vmt.GetHashCode)
                recM.name = clsName + "." + "GetHashCode";
            else if (m == Vmt.ToString)
                recM.name = clsName + "." + "ToString";
            if (recM.name != "" && KnowledgeBase.GetKBProcInfo(recM.name, pInfo, &idx))
                StrapProc(Adr2Pos(recM.address), idx, pInfo, true, pInfo->DumpSz);
        }
        recN->vmtInfo->AddMethod(recM.abstract, 'V', m, recM.address, recM.name);
    }
}
//---------------------------------------------------------------------------
