//---------------------------------------------------------------------------
#include <vcl.h>
#pragma hdrstop
//---------------------------------------------------------------------------
#include <stdio.h>
#include <assert>

#include "Disasm.h"
#include "Misc.h"
//---------------------------------------------------------------------------

static void* (__stdcall* PStreamNew)();
static void* (__stdcall* PdisNew)(int);
static void  (__stdcall* SetAddr64)(void*, bool);
static int   (__stdcall* CchFormatInstr)(wchar_t*, DWORD);
static void  *DISX86;

static const char*   rgszBase16[] =
{
    "bx+si", "bx+di", "bp+si", "bp+di", "si", "di", "bp", "bx"
};
static const char*   rgszSReg[] =
{
    "es", "cs", "ss", "ds", "fs", "gs"
};
static const char*   rgszReg64[] =
{
    "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"
};
static const char*   rgszReg32[] =
{
    "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi", "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d"
};
static const char*   rgszReg16[] =
{
    "ax", "cx", "dx", "bx", "sp", "bp", "si", "di", "r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w"
};
static const char*   rgszReg8New[] =
{
    "al", "cl", "dl", "bl", "spl", "bpl", "sil", "dil", "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b"
};
static const char*   rgszReg8[] =
{
    "ah", "ch", "dh", "bh"
};
static const char*  stRegs[] =
{
    "st(0)", "st(1)", "st(2)", "st(3)", "st(4)", "st(5)", "st(6)", "st(7)"
};
static const char*  mmRegs[] =
{
    "mm0", "mm1", "mm2", "mm3", "mm4", "mm5", "mm6", "mm7"
};
static const char*  xmmRegs[] =
{
    "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7",
    "xmm8", "xmm9", "xmm10", "xmm11", "xmm12", "xmm13", "xmm14", "xmm15"
};
static const char*  ymmRegs[] =
{
    "ymm0", "ymm1", "ymm2", "ymm3", "ymm4", "ymm5", "ymm6", "ymm7",
    "ymm8", "ymm9", "ymm10", "ymm11", "ymm12", "ymm13", "ymm14", "ymm15"
};
static const char*  crRegs[] =
{
    "cr0", "cr1", "cr2", "cr3", "cr4", "cr5", "cr6", "cr7",
    "cr8", "cr9", "cr10", "cr11", "cr12", "cr13", "cr14", "cr15"
};
static const char*  drRegs[] =
{
    "dr0", "dr1", "dr2", "dr3", "dr4", "dr5", "dr6", "dr7",
    "dr8", "dr9", "dr10", "dr11", "dr12", "dr13", "dr14", "dr15"
};
static const char*  trRegs[] =
{
    "tr0", "tr1", "tr2", "tr3", "tr4", "tr5", "tr6", "tr7",
    "tr8", "tr9", "tr10", "tr11", "tr12", "tr13", "tr14", "tr15"
};

static const char*   RepPrefixes[] =
{
    "lock", "repne", "repe", "rep", "hnt", "ht", "xacquire", "xrelease"
};
static const char*   SimilarRegs[] =
{
    "alahaxeaxrax",
    "clchcxecxrcx",
    "dldhdxedxrdx",
    "blbhbxebxrbx",
    "splspesprsp",
    "bplbpebprbp",
    "silsiesirsi",
    "dildiedirdi",
    "r8br8wr8dr8",
    "r9br9wr9dr9",
    "r10br10wr10dr10",
    "r11br11wr11dr11",
    "r12br12wr12dr12",
    "r13br13wr13dr13",
    "r14br14wr14dr14",
    "r15br15wr15dr15",
    "mm0xmm0",
    "mm1xmm1",
    "mm2xmm2",
    "mm3xmm3",
    "mm4xmm4",
    "mm5xmm5",
    "mm6xmm6",
    "mm7xmm7",
};

static const OPSIZE_INFO OpSizes[] =
{
    {1,  "byte"},
    {2,  "word"},
    {4,  "dword"},
    {6,  "fword"},
    {8,  "qword"},
    {8,  "mmword"},
    {10, "tbyte"},
    {16, "xmmword"},
    {16, "oword"},
    {32, "ymmword"}
};

static const int ValidInstructions[] =
{
IDX_ADC,
IDX_ADD,
IDX_ADDSD,
IDX_ADDSS,
IDX_AESDEC,
IDX_AESDECLAST,
IDX_AESENC,
IDX_AESENCLAST,
IDX_AESIMC,
IDX_AESKEYGENASSIST,
IDX_AND,
IDX_ANDPD,
IDX_BSF,
IDX_BSR,
IDX_BSWAP,
IDX_BT,
IDX_BTC,
IDX_BTR,
IDX_BTS,
IDX_CALL,
IDX_CDQ,
IDX_CDQE,
IDX_CLC,
IDX_CLD,
IDX_CMOVA,
IDX_CMOVB,
IDX_CMOVBE,
IDX_CMOVE,
IDX_CMOVG,
IDX_CMOVNE,
IDX_CMP,
IDX_CMPS,
IDX_CMPXCHG,
IDX_COMISD,
IDX_COMISS,
IDX_CPUID,
IDX_CQO,
IDX_CRC32,
IDX_CVTDQ2PD,
IDX_CVTDQ2PS,
IDX_CVTPD2DQ,
IDX_CVTPD2PI,
IDX_CVTPD2PS,
IDX_CVTPI2PD,
IDX_CVTPI2PS,
IDX_CVTPS2DQ,
IDX_CVTPS2PD,
IDX_CVTPS2PI,
IDX_CVTSD2SI,
IDX_CVTSD2SS,
IDX_CVTSI2SD,
IDX_CVTSI2SS,
IDX_CVTSS2SD,
IDX_CVTSS2SI,
IDX_CVTTPD2DQ,
IDX_CVTTPD2PI,
IDX_CVTTPS2DQ,
IDX_CVTTPS2PI,
IDX_CVTTSD2SI,
IDX_CVTTSS2SI,
IDX_DEC,
IDX_DIV,
IDX_DIVSD,
IDX_DIVSS,
IDX_EMMS,
IDX_ENTER,
IDX_FLD,
IDX_FLDCW,
IDX_FMUL,
IDX_FNCLEX,
IDX_FNSTCW,
IDX_FSUBP,
IDX_HLT,
IDX_IDIV,
IDX_IMUL,
IDX_IN,
IDX_INC,
IDX_INS,
IDX_INT,
IDX_JA,
IDX_JAE,
IDX_JB,
IDX_JBE,
IDX_JE,
IDX_JG,
IDX_JGE,
IDX_JL,
IDX_JLE,
IDX_JMP,
IDX_JNE,
IDX_JNS,
IDX_JO,
IDX_JP,
IDX_JS,
IDX_LAHF,
IDX_LDMXCSR,
IDX_LEA,
IDX_LODS,
IDX_LOOPE,
IDX_LOOPNE,
IDX_MOV,
IDX_MOVAPD,
IDX_MOVAPS,
IDX_MOVD,
IDX_MOVDQA,
IDX_MOVDQU,
IDX_MOVQ,
IDX_MOVS,
IDX_MOVSD,
IDX_MOVSS,
IDX_MOVSX,
IDX_MOVSXD,
IDX_MOVUPS,
IDX_MOVZX,
IDX_MUL,
IDX_MULSD,
IDX_MULSS,
IDX_NEG,
IDX_NOP,
IDX_NOT,
IDX_OR,
IDX_ORPD,
IDX_OUT,
IDX_OUTS,
IDX_PACKUSWB,
IDX_PADDD,
IDX_PADDUSB,
IDX_PADDW,
IDX_PAND,
IDX_PAUSE,
IDX_PMAXUB,
IDX_PMINUB,
IDX_PMULHW,
IDX_PMULLW,
IDX_POP,
IDX_POPFQ,
IDX_POR,
IDX_PSHUFD,
IDX_PSHUFLW,
IDX_PSHUFW,
IDX_PSLLDQ,
IDX_PSLLW,
IDX_PSRLQ,
IDX_PSRLW,
IDX_PSUBUSB,
IDX_PSUBUSW,
IDX_PSUBW,
IDX_PUNPCKHDQ,
IDX_PUNPCKHWD,
IDX_PUNPCKLBW,
IDX_PUNPCKLDQ,
IDX_PUNPCKLWD,
IDX_PUSH,
IDX_PUSHFQ,
IDX_PXOR,
IDX_RDTSC,
IDX_RET,
IDX_ROL,
IDX_ROR,
IDX_SAR,
IDX_SBB,
IDX_SETA,
IDX_SETAE,
IDX_SETB,
IDX_SETBE,
IDX_SETE,
IDX_SETG,
IDX_SETGE,
IDX_SETL,
IDX_SETLE,
IDX_SETNE,
IDX_SETNP,
IDX_SETP,
IDX_SHL,
IDX_SHLD,
IDX_SHR,
IDX_SHRD,
IDX_SHUFPS,
IDX_SQRTSD,
IDX_SQRTSS,
IDX_STC,
IDX_STI,
IDX_STMXCSR,
IDX_STOS,
IDX_STR,
IDX_SUB,
IDX_SUBSD,
IDX_SUBSS,
IDX_TEST,
IDX_UCOMISD,
IDX_UCOMISS,
IDX_WAIT,
IDX_XADD,
IDX_XCHG,
IDX_XLAT,
IDX_XOR,
IDX_XORPD,
IDX_XORPS
};
//---------------------------------------------------------------------------
__fastcall MDisasm::MDisasm(TCriticalSection* cs)
    :_cs(cs), FormatInstrStops(0) 
{
    hModule = 0;
    PdisNew = 0;
}
//---------------------------------------------------------------------------
void __fastcall MDisasm::Free()
{
    if (DISX86)
    {
        asm //Call destructor of class DISX86
        {
            push    1
            mov     ecx, [DISX86]
            mov     eax, [ecx]
            call    dword ptr [eax]
        }
        DISX86 = 0;
    }
    if (hModule)
    {
        FreeLibrary(hModule);
        hModule = 0;
    }
}
//---------------------------------------------------------------------------
__fastcall MDisasm::~MDisasm()
{
    Free();
}
//---------------------------------------------------------------------------
int __fastcall MDisasm::Init()
{
    try
    {
        hModule = LoadLibrary("msvcdis110.dll");
        if (!hModule) throw Exception("engine not found");

        PStreamNew = (void* (__stdcall*)())GetProcAddress(hModule, "?PwostrstreamNew@wostrstream@DIS@@SGPAV12@XZ");
        PdisNew = (void* (__stdcall*)(int))GetProcAddress(hModule, "?PdisNew@DIS@@SGPAV1@W4DIST@1@@Z");
        SetAddr64 = (void (__stdcall*)(void*, bool))GetProcAddress(hModule, "?SetAddr64@DIS@@QAEX_N@Z");
        CchFormatInstr = (int (_stdcall*)(wchar_t*, DWORD))GetProcAddress(hModule, "?CchFormatInstr@DIS@@QBEIPA_WI@Z");

        if (PdisNew)
            DISX86 = PdisNew(ENCODING64);

        if (! (PStreamNew && PdisNew && SetAddr64 && CchFormatInstr && DISX86))
        {
            Free();
            return 0;
        }
        #define     SetAddr64Offset  0x1005B480
        mpopaszMnemonicOffset = (wchar_t**)((BYTE*)SetAddr64 + (0x10024488 - SetAddr64Offset));
        int     _FormatInstrStops;
        asm
        {
            mov     ecx, [DISX86]
            mov     al, 1
            call    SetAddr64
            mov     ecx, [DISX86]
            mov     eax, [ecx+1C8h]
            mov     [_FormatInstrStops], eax
        }
        FormatInstrStops = _FormatInstrStops;
    }
    catch (Exception& e)
    {
        ShowMessage("Exception on initialize Disasm: "+e.Message);
        Free();
        return 0;
    }
    return 1;
}
//---------------------------------------------------------------------------
BYTE __fastcall MDisasm::GetOp(int Idx)
{
    if (Idx == IDX_MOV || Idx == IDX_MOVD || Idx == IDX_MOVQ ||
        (Idx >= IDX_CVTDQ2PD && Idx <= IDX_CVTTSS2SI))
        return OP_MOV;
    if (Idx == IDX_MOVS || Idx == IDX_MOVSD || Idx == IDX_MOVSS ||
        Idx == IDX_MOVSX || Idx == IDX_MOVSXD || Idx == IDX_MOVZX)
        return OP_MOVS;
    if (Idx == IDX_PUSH)
        return OP_PUSH;
    if (Idx == IDX_POP)
        return OP_POP;
    if (Idx == IDX_JMP)
        return OP_JMP;
    if (Idx == IDX_XOR || Idx == IDX_XORPD || Idx == IDX_XORPS)
        return OP_XOR;
    if (Idx == IDX_CMP || Idx == IDX_COMISD || Idx == IDX_COMISS ||
        Idx == IDX_UCOMISD || Idx == IDX_UCOMISS || Idx == IDX_CMPXCHG)
        return OP_CMP;
    if (Idx == IDX_TEST)
        return OP_TEST;
    if (Idx == IDX_LEA)
        return OP_LEA;
    if (Idx >= IDX_ADD && Idx <= IDX_ADDSS)
        return OP_ADD;
    if (Idx >= IDX_SUB && Idx <= IDX_SUBSS)
        return OP_SUB;
    if (Idx >= IDX_OR && Idx <= IDX_ORPS)
        return OP_OR;
    if (Idx >= IDX_AND && Idx <= IDX_ANDPS)
        return OP_AND;
    if (Idx == IDX_INC)
        return OP_INC;
    if (Idx == IDX_DEC)
        return OP_DEC;
    if (Idx >= IDX_MUL && Idx <= IDX_MULSS)
        return OP_MUL;
    if (Idx >= IDX_DIV && Idx <= IDX_DIVSS)
        return OP_DIV;
    if (Idx == IDX_IMUL)
        return OP_IMUL;
    if (Idx == IDX_IDIV)
        return OP_IDIV;
    if (Idx == IDX_SHL || Idx == IDX_SHLD)
        return OP_SHL;
    if (Idx == IDX_SHR || Idx == IDX_SHRD)
        return OP_SHR;
    if (Idx == IDX_SAL)
        return OP_SAL;
    if (Idx == IDX_SAR)
        return OP_SAR;
    if (Idx == IDX_NEG)
        return OP_NEG;
    if (Idx == IDX_NOT)
        return OP_NOT;
    if (Idx == IDX_ADC)
        return OP_ADC;
    if (Idx == IDX_SBB)
        return OP_SBB;
    if (Idx == IDX_CDQ)
        return OP_CDQ;
    if (Idx == IDX_XCHG)
        return OP_XCHG;
    if (Idx == IDX_BT)
        return OP_BT;
    if (Idx == IDX_BTC)
        return OP_BTC;
    if (Idx == IDX_BTR)
        return OP_BTR;
    if (Idx == IDX_BTS)
        return OP_BTS;
    if (Idx >= IDX_SETA && Idx <= IDX_SETS)
        return OP_SET;
    return OP_UNK;
}
//---------------------------------------------------------------------------
int __fastcall MDisasm::Disassemble(BYTE* from, ULONGLONG address, PDISINFO pDisInfo, char* disLine)
{
	int	        InstrLen, _res, _mnemIdx;
    int         *p1;
	char        *p, *q, *pInstr;
    wchar_t     wInstr[1024];
    String      Instr;

    DataGuard dg(_cs); //<- starting from this point code is synchronized (allow only 1 thread to execute)

    asm
    {
        push    64h
        mov     ecx, [DISX86]
        mov     eax, [ecx]
        push    [from]
        push    dword ptr [address + 4]
        push    dword ptr [address]
        call    dword ptr [eax+20h]     //CbDisassemble
        mov     [InstrLen], eax
    }
    //If pDisInfo = NULL return only instruction length
    if (pDisInfo)
    {
        if (InstrLen)
        {
            memset(pDisInfo, 0, sizeof(DISINFO));
            pDisInfo->OpRegIdx[0] = -1;
            pDisInfo->OpRegIdx[1] = -1;
            pDisInfo->OpRegIdx[2] = -1;
            pDisInfo->BaseReg = -1;
            pDisInfo->IndxReg = -1;
            pDisInfo->RepPrefix = -1;
            pDisInfo->SegPrefix = -1;

            asm
            {
                push    400h
                lea     eax, [wInstr]
                push    eax
                mov     ecx, [DISX86]
                call    CchFormatInstr
            }
            
            Instr = WideString(wInstr);
            pInstr = Instr.c_str();
            if (disLine) strcpy(disLine, pInstr);
            if (!ParseInstr(pDisInfo, pInstr))
            {
                return 0;
            }

            if (pDisInfo->IndxReg != -1 && !pDisInfo->Scale) pDisInfo->Scale = 1;

            _mnemIdx = pDisInfo->MnemIdx;

            if ((_mnemIdx >= IDX_F2XM1 && _mnemIdx <= IDX_FYL2XP1) || _mnemIdx == IDX_WAIT)
            {
                pDisInfo->Float = true;
            }
            else if (_mnemIdx >= IDX_JA && _mnemIdx <= IDX_JS)
            {
                pDisInfo->Branch = true;
                if (_mnemIdx != IDX_JMP) pDisInfo->Conditional = true;
            }
            else if (_mnemIdx == IDX_CALL)
            {
                pDisInfo->Call = true;
            }
            else if (_mnemIdx == IDX_RET)
            {
                pDisInfo->Ret = true;
            }
            _res = InstrLen;
        }
        else
        {
            _res = 0;
        }
    }
    else
    {
        _res = InstrLen;
    }
	return _res;
}
//---------------------------------------------------------------------------
int __fastcall MDisasm::IsPrefix(const char* pItem)
{
    for (int n = 0; n < ARRAYSIZE(RepPrefixes); n++)
    {
        if (!strcmp(pItem, RepPrefixes[n]))
            return n;
    }
    return -1;
}
//---------------------------------------------------------------------------
int __fastcall MDisasm::IsOpSize(const char* pItem)
{
    for (int n = 0; n < ARRAYSIZE(OpSizes); n++)
    {
        if (!strcmp(pItem, OpSizes[n].name))
            return OpSizes[n].size;
    }
    return -1;
}
//---------------------------------------------------------------------------
String __fastcall MDisasm::GetOpSizeName(int Size)
{
    for (int n = 0; n < ARRAYSIZE(OpSizes); n++)
    {
        if (Size == OpSizes[n].size)
            return String(OpSizes[n].name);
    }
    return "?";
}
//---------------------------------------------------------------------------
String __fastcall MDisasm::GetMnemonic(int Idx)
{
    wchar_t     *wInstr;

    wInstr = mpopaszMnemonicOffset[Idx];
    return WideString(wInstr);
}
//---------------------------------------------------------------------------
int __fastcall MDisasm::IsReg(const char* pItem)
{
    char    c0, c1;
    int     n;

    if (!pItem) return -1;

    c0 = pItem[0]; if (!c0) return -1;
    
    for (n = 0; n < ARRAYSIZE(rgszReg32); n++)
    {
        if (!strcmp(pItem, rgszReg32[n]))
            return n + REG_EAX;
    }
    for (n = 0; n < ARRAYSIZE(rgszReg64); n++)
    {
        if (!strcmp(pItem, rgszReg64[n]))
            return n + REG_RAX;
    }
    for (n = 0; n < ARRAYSIZE(rgszReg16); n++)
    {
        if (!strcmp(pItem, rgszReg16[n]))
            return n + REG_AX;
    }
    for (n = 0; n < ARRAYSIZE(rgszReg8New); n++)
    {
        if (!strcmp(pItem, rgszReg8New[n]))
            return n + REG_AL;
    }
    for (n = 0; n < ARRAYSIZE(rgszReg8); n++)
    {
        if (!strcmp(pItem, rgszReg8[n]))
            return n + REG_AH;
    }
    for (n = 0; n < ARRAYSIZE(rgszSReg); n++)
    {
        if (!strcmp(pItem, rgszSReg[n]))
            return n + REG_ES;
    }
    c1 = pItem[1];
    if (c0 == 's' && c1 == 't') return (pItem[3] - '0') + REG_ST0;
    if (c0 == 'm' && c1 == 'm') return (pItem[2] - '0') + REG_MM0;
    if (c0 == 'x' && c1 == 'm') return atoi(pItem + 3) + REG_XMM0;
    if (c0 == 'y' && c1 == 'm') return atoi(pItem + 3) + REG_YMM0;
    if (c0 == 'c' && c1 == 'r') return atoi(pItem + 2) + REG_CR0;
    if (c0 == 'd' && c1 == 'r') return atoi(pItem + 2) + REG_DR0;
    if (c0 == 't' && c1 == 'r') return (pItem[2] - '0') + REG_TR0;
    return -1;
}
//---------------------------------------------------------------------------
int __fastcall MDisasm::GetItem(char* src, char* dst)
{
    char    c;
    int     n;

    dst[0] = 0;
    for (n = 0;; n++)
    {
        c = src[n];
        if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '(' || c == ')')   //st()
        {
            dst[n] = c;
            continue;
        }
        break;
    }
    dst[n] = 0;
    return n;
}
//---------------------------------------------------------------------------
int __fastcall MDisasm::GetNumber(char* src, char* dst)
{
    char    c;
    int     n;

    dst[0] = 0;
    for (n = 0;; n++)
    {
        c = src[n];
        if ((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || c == 'h')
        {
            dst[n] = c;
            continue;
        }
        break;
    }
    dst[n] = 0;
    return n;
}
//---------------------------------------------------------------------------
bool __fastcall MDisasm::ParseInstr(PDISINFO pDisInfo, char* pInstr)
{
    bool        negOfs;
    char        c;
    int         n, InstrLen, ItemLen, Opa, iVal, OpNo, OpNum;
    int         BaseRegIdx, IndexRegIdx;
    char        *pMnemonic;
    String      sMnem;
    char        Item[32];

    asm
    {
        mov     ecx, [DISX86]
        mov     eax, [ecx]
        call    dword ptr [eax+5Ch]
        mov     [Opa], eax
    }

    sMnem = GetMnemonic(Opa);
    pMnemonic = sMnem.c_str();

    InstrLen = strlen(pInstr); OpNo = -1; OpNum = 0;
    for (n = 0; n < InstrLen;)
    {
        c = pInstr[n];
        if (!c) break;
        if (c == ' ' || c == ',')
        {
            n++;
            continue;
        }
        if (c == '[')
        {
            OpNo++; OpNum++;
            BaseRegIdx = IndexRegIdx = -1; negOfs = false;
            pDisInfo->OpType[OpNo] = otMEM;
            n++;    //Skip '['
            while (1)
            {
                c = pInstr[n];
                if (c >= '0' && c <= 'F')   //Number - offset or scale
                {
                    if (pInstr[n - 1] == '*')   //Previous symbol is '*' - scale
                    {
                        ItemLen = GetNumber(&pInstr[n], Item);
                        sscanf(Item, "%lX", &pDisInfo->Scale);
                    }
                    else
                    {
                        ItemLen = GetNumber(&pInstr[n], Item);
                        sscanf(Item, "%lX", &pDisInfo->Offset);
                        if (negOfs)
                        {
                            pDisInfo->Offset = -pDisInfo->Offset;
                        }
                    }
                    n += ItemLen;
                    continue;
                }
                if (c >= 'a' && c <= 'z')   //Letter - register
                {
                    ItemLen = GetItem(&pInstr[n], Item);
                    if (BaseRegIdx == -1)
                    {
                        BaseRegIdx = IsReg(Item);
                        pDisInfo->BaseReg = BaseRegIdx;
                        n += ItemLen;
                        continue;
                    }
                    if (IndexRegIdx == -1)
                    {
                        IndexRegIdx = IsReg(Item);
                        pDisInfo->IndxReg = IndexRegIdx;
                        n += ItemLen;
                        continue;
                    }
                }
                if (c == '+' || c == '-' || c == '*')
                {
                    if (c == '-')
                    {
                         negOfs = true;
                    }
                    n++;
                    continue;
                }
                if (c == ']')
                {
                    n++;
                    break;
                }
            }
            continue;
        }
        if (c >= 'a' && c <= 'z')
        {
            ItemLen = GetItem(&pInstr[n], Item);

            if ((iVal = IsPrefix(Item)) != -1)
            {
                pDisInfo->RepPrefix = iVal;
                n += ItemLen;
                continue;
            }
            if (!stricmp(Item, pMnemonic))
            {
                //strcpy(pDisInfo->Mnem, pMnemonic);
                pDisInfo->MnemIdx = Opa;
                n += ItemLen;
                continue;
            }
            if ((iVal = IsOpSize(Item)) != -1)
            {
                pDisInfo->OpSize = iVal;
                n += ItemLen;
                continue;
            }
            if ((iVal = IsReg(Item)) >= 0)  //Register
            {
                if (iVal >= REG_ES && iVal <= REG_GS && pInstr[n + 2] == ':')   //Segment prefix
                {
                    pDisInfo->SegPrefix = iVal;
                    n++;    //Skip ':'
                }
                else
                {
                    OpNo++; OpNum++;
                    pDisInfo->OpRegIdx[OpNo] = iVal;
                    pDisInfo->OpType[OpNo] = otREG;
                    if (iVal >= REG_ST0 && iVal <= REG_ST7)
                    {
                        pDisInfo->OpType[OpNo] = otFST;
                    }
                }
                n += ItemLen;
                continue;
            }
            n += ItemLen;
            continue;
        }
        if (c >= '0' && c <= 'F')
        {
            OpNo++; OpNum++;
            ItemLen = GetNumber(&pInstr[n], Item);
            sscanf(Item, "%lX", &pDisInfo->Immediate);
            pDisInfo->OpType[OpNo] = otIMM;
            n += ItemLen;
            if (pInstr[n] == ':')   //Something like call (jmp) XXX:YYY
            {
                return false;
            }
            continue;
        }
    }
    pDisInfo->OpNum = OpNum;
    return true;
}
//---------------------------------------------------------------------------
const char* __fastcall MDisasm::GetAsmRegisterNameInternal(int Idx)
{
    assert(Idx >= REG_EAX && Idx <= REG_TR7);
    if (Idx <= REG_R15D) return rgszReg32[Idx];
    if (Idx <= REG_R15) return rgszReg64[Idx - REG_RAX];
    if (Idx <= REG_R15W) return rgszReg16[Idx - REG_AX];
    if (Idx <= REG_R15B) return rgszReg8New[Idx - REG_AL];
    if (Idx <= REG_BH) return rgszReg8[Idx - REG_AH];
    if (Idx <= REG_GS) return rgszSReg[Idx - REG_ES];
    if (Idx <= REG_ST7) return stRegs[Idx - REG_ST0];
    if (Idx <= REG_MM7) return mmRegs[Idx - REG_MM0];
    if (Idx <= REG_XMM15) return xmmRegs[Idx - REG_XMM0];
    if (Idx <= REG_YMM15) return ymmRegs[Idx - REG_YMM0];
    if (Idx <= REG_CR15) return crRegs[Idx - REG_CR0];
    if (Idx <= REG_DR15) return drRegs[Idx - REG_DR0];
    return trRegs[Idx - REG_TR0];
}
//---------------------------------------------------------------------------
String __fastcall MDisasm::GetAsmRegisterName(int Idx)
{
    return String(GetAsmRegisterNameInternal(Idx));
}
//---------------------------------------------------------------------------
bool __fastcall MDisasm::IsSimilarRegs(const char* Reg1, const char* Reg2)
{
    int         n, m;

    const int numl = ARRAYSIZE(SimilarRegs);
    for (n = 0; n < numl; n++)
    {
        if (strstr(SimilarRegs[n], Reg1)) break;
    }
    for (m = 0; m < numl; m++)
    {
        if (strstr(SimilarRegs[m], Reg2)) break;
    }
    if (n < numl && m < numl && n == m) return true;

    return false;
}
//---------------------------------------------------------------------------
bool __fastcall MDisasm::IsSimilarRegs(int Idx1, int Idx2)
{
    return IsSimilarRegs(GetAsmRegisterNameInternal(Idx1), GetAsmRegisterNameInternal(Idx2));
}
//---------------------------------------------------------------------------
const char* MDisasm::GetrgszReg32(int i) const
{
    return (i>=0 && i<ARRAYSIZE(rgszReg32)) ? rgszReg32[i] : "?";
}

const char* MDisasm::GetrgszSReg(int i) const
{
    return (i>=0 && i<ARRAYSIZE(rgszSReg)) ? rgszSReg[i] : "?";     
}
const char* MDisasm::GetRepPrefixes(int i) const
{
    return (i>=0 && i<ARRAYSIZE(RepPrefixes)) ? RepPrefixes[i] : "?";
}
//---------------------------------------------------------------------------
bool __fastcall MDisasm::IsValidInstruction(int InstrIdx)
{
    int Idx, F = 0, L = ARRAYSIZE(ValidInstructions) - 1;
    while (F < L)
    {
        int M = (F + L)/2;
        Idx = ValidInstructions[M];
        if (InstrIdx <= Idx)
            L = M;
        else
            F = M + 1;
    }
    if (InstrIdx == Idx) return true;
    return false;
}
//---------------------------------------------------------------------------
