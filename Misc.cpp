//---------------------------------------------------------------------------
#include <vcl.h>
#pragma hdrstop

#include <Clipbrd.hpp>
#include <Imagehlp.h>
#include <assert>

#include "Misc.h"
#include "Resources.h"
//---------------------------------------------------------------------------
//global instance (TBD: think about Singleton pattern & API like getIdr() )
Idr64Manager idr;
DelphiVmt Vmt;

//as some statistics for memory leaks detection (remove it when fixed)
static long stat_InfosOverride = 0;
//---------------------------------------------------------------------------

//TBD: refactor any extern usage (delme)
// ideally: all these vars/dbs/etc must be kept private inside idr manager!
//
extern  int         dummy;
extern  DWORD       EP;
//extern  String      IDR64Version;
extern  String      SelectedAsmItem;
//extern  char        StringBuf[MAXSTRBUFFER];
extern  DWORD       ImageBase;
extern  DWORD       ImageSize;
extern  DWORD       TotalSize;
extern  DWORD       CodeBase;
extern  DWORD       CodeSize;

extern  BYTE        *Image;
//extern  PInfoRec    *Infos;
extern  TStringList *BSSInfos;
//extern  MDisasm     Disasm;
extern  MKnowledgeBase  KnowledgeBase;
extern  BYTE        *Code;
extern  TList       *SegmentList;
extern  TList       *OwnTypeList;
extern  TList       *VmtList;


extern DWORD        HInstanceVarAdr;
extern DWORD        LastTls;

//Units
extern int          UnitsNum;
extern TList        *Units;

//---------------------------------------------------------------------------

static MsgInfo  WindowsMsgTab[] =
{
{1, "WMCreate", "WM_CREATE"},
{2, "WMDestroy", "WM_DESTROY"},
{3, "WMMove", "WM_MOVE"},
{5, "WMSize", "WM_SIZE"},
{6, "WMActivate", "WM_ACTIVATE"},
{7, "WMSetFocus", "WM_SETFOCUS"},
{8, "WMKillFocus", "WM_KILLFOCUS"},
{0xA, "WMEnable", "WM_ENABLE"},
{0xB, "WMSetRedraw", "WM_SETREDRAW"},
{0xC, "WMSetText", "WM_SETTEXT"},
{0xD, "WMGetText", "WM_GETTEXT"},
{0xE, "WMGetTextLength", "WM_GETTEXTLENGTH"},
{0xF, "WMPaint", "WM_PAINT"},
{0x10, "WMClose", "WM_CLOSE"},
{0x11, "WMQueryEndSession", "WM_QUERYENDSESSION"},
{0x12, "WMQuit", "WM_QUIT"},
{0x13, "WMQueryOpen", "WM_QUERYOPEN"},
{0x14, "WMEraseBkgnd", "WM_ERASEBKGND"},
{0x15, "WMSysColorChange", "WM_SYSCOLORCHANGE"},
{0x16, "WMEndSession", "WM_ENDSESSION"},
{0x17, "WMSystemError", "WM_SYSTEMERROR"},
{0x18, "WMShowWindow", "WM_SHOWWINDOW"},
{0x19, "WMCtlColor", "WM_CTLCOLOR"},
{0x1A, "WMSettingChange", "WM_SETTINGCHANGE"},
{0x1B, "WMDevModeChange", "WM_DEVMODECHANGE"},
{0x1C, "WMActivateApp", "WM_ACTIVATEAPP"},
{0x1D, "WMFontChange", "WM_FONTCHANGE"},
{0x1E, "WMTimeChange", "WM_TIMECHANGE"},
{0x1F, "WMCancelMode", "WM_CANCELMODE"},
{0x20, "WMSetCursor", "WM_SETCURSOR"},
{0x21, "WMMouseActivate", "WM_MOUSEACTIVATE"},
{0x22, "WMChildActivate", "WM_CHILDACTIVATE"},
{0x23, "WMQueueSync", "WM_QUEUESYNC"},
{0x24, "WMGetMinMaxInfo", "WM_GETMINMAXINFO"},
{0x26, "WMPaintIcon", "WM_PAINTICON"},
{0x27, "WMEraseBkgnd", "WM_ICONERASEBKGND"},
{0x28, "WMNextDlgCtl", "WM_NEXTDLGCTL"},
{0x2A, "WMSpoolerStatus", "WM_SPOOLERSTATUS"},
{0x2B, "WMDrawItem", "WM_DRAWITEM"},
{0x2C, "WMMeasureItem", "WM_MEASUREITEM"},
{0x2D, "WMDeleteItem", "WM_DELETEITEM"},
{0x2E, "WMVKeyToItem", "WM_VKEYTOITEM"},
{0x2F, "WMCharToItem", "WM_CHARTOITEM"},
{0x30, "WMSetFont", "WM_SETFONT"},
{0x31, "WMGetFont", "WM_GETFONT"},
{0x32, "WMSetHotKey", "WM_SETHOTKEY"},
{0x33, "WMGetHotKey", "WM_GETHOTKEY"},
{0x37, "WMQueryDragIcon", "WM_QUERYDRAGICON"},
{0x39, "WMCompareItem", "WM_COMPAREITEM"},
//{0x3D, "?", "WM_GETOBJECT"},
{0x41, "WMCompacting", "WM_COMPACTING"},
//{0x44, "?", "WM_COMMNOTIFY"},
{0x46, "WMWindowPosChangingMsg", "WM_WINDOWPOSCHANGING"},
{0x47, "WMWindowPosChangedMsg", "WM_WINDOWPOSCHANGED"},
{0x48, "WMPower", "WM_POWER"},
{0x4A, "WMCopyData", "WM_COPYDATA"},
//{0x4B, "?", "WM_CANCELJOURNAL"},
{0x4E, "WMNotify", "WM_NOTIFY"},
//{0x50, "?", "WM_INPUTLANGCHANGEREQUEST"},
//{0x51, "?", "WM_INPUTLANGCHANGE"},
//{0x52, "?", "WM_TCARD"},
{0x53, "WMHelp", "WM_HELP"},
//{0x54, "?", "WM_USERCHANGED"},
{0x55, "WMNotifyFormat", "WM_NOTIFYFORMAT"},
{0x7B, "WMContextMenu", "WM_CONTEXTMENU"},
{0x7C, "WMStyleChanging", "WM_STYLECHANGING"},
{0x7D, "WMStyleChanged", "WM_STYLECHANGED"},
{0x7E, "WMDisplayChange", "WM_DISPLAYCHANGE"},
{0x7F, "WMGetIcon", "WM_GETICON"},
{0x80, "WMSetIcon", "WM_SETICON"},
{0x81, "WMNCCreate", "WM_NCCREATE"},
{0x82, "WMNCDestroy", "WM_NCDESTROY"},
{0x83, "WMNCCalcSize", "WM_NCCALCSIZE"},
{0x84, "WMNCHitTest", "WM_NCHITTEST"},
{0x85, "WMNCPaint", "WM_NCPAINT"},
{0x86, "WMNCActivate", "WM_NCACTIVATE"},
{0x87, "WMGetDlgCode", "WM_GETDLGCODE"},
{0xA0, "WMNCMouseMove", "WM_NCMOUSEMOVE"},
{0xA1, "WMNCLButtonDown", "WM_NCLBUTTONDOWN"},
{0xA2, "WMNCLButtonUp", "WM_NCLBUTTONUP"},
{0xA3, "WMNCLButtonDblClk", "WM_NCLBUTTONDBLCLK"},
{0xA4, "WMNCRButtonDown", "WM_NCRBUTTONDOWN"},
{0xA5, "WMNCRButtonUp", "WM_NCRBUTTONUP"},
{0xA6, "WMNCRButtonDblClk", "WM_NCRBUTTONDBLCLK"},
{0xA7, "WMNCMButtonDown", "WM_NCMBUTTONDOWN"},
{0xA8, "WMNCMButtonUp", "WM_NCMBUTTONUP"},
{0xA9, "WMNCMButtonDblClk", "WM_NCMBUTTONDBLCLK"},
{0x100, "WMKeyDown", "WM_KEYDOWN"},
{0x101, "WMKeyUp", "WM_KEYUP"},
{0x102, "WMChar", "WM_CHAR"},
{0x103, "WMDeadChar", "WM_DEADCHAR"},
{0x104, "WMSysKeyDown", "WM_SYSKEYDOWN"},
{0x105, "WMSysKeyUp", "WM_SYSKEYUP"},
{0x106, "WMSysChar", "WM_SYSCHAR"},
{0x107, "WMSysDeadChar", "WM_SYSDEADCHAR"},
//{0x108, "?", "WM_KEYLAST"},
//{0x10D, "?", "WM_IME_STARTCOMPOSITION"},
//{0x10E, "?", "WM_IME_ENDCOMPOSITION"},
//{0x10F, "?", "WM_IME_COMPOSITION"},
{0x110, "WMInitDialog", "WM_INITDIALOG"},
{0x111, "WMCommand", "WM_COMMAND"},
{0x112, "WMSysCommand", "WM_SYSCOMMAND"},
{0x113, "WMTimer", "WM_TIMER"},
{0x114, "WMHScroll", "WM_HSCROLL"},
{0x115, "WMVScroll", "WM_VSCROLL"},
{0x116, "WMInitMenu", "WM_INITMENU"},
{0x117, "WMInitMenuPopup", "WM_INITMENUPOPUP"},
{0x11F, "WMMenuSelect", "WM_MENUSELECT"},
{0x120, "WMMenuChar", "WM_MENUCHAR"},
{0x121, "WMEnterIdle", "WM_ENTERIDLE"},
//{0x122, "?", "WM_MENURBUTTONUP"},
//{0x123, "?", "WM_MENUDRAG"},
//{0x124, "?", "WM_MENUGETOBJECT"},
//{0x125, "?", "WM_UNINITMENUPOPUP"},
//{0x126, "?", "WM_MENUCOMMAND"},
{0x127, "WMChangeUIState", "WM_CHANGEUISTATE"},
{0x128, "WMUpdateUIState", "WM_UPDATEUISTATE"},
{0x129, "WMQueryUIState", "WM_QUERYUISTATE"},
{0x132, "WMCtlColorMsgBox", "WM_CTLCOLORMSGBOX"},
{0x133, "WMCtlColorEdit", "WM_CTLCOLOREDIT"},
{0x134, "WMCtlColorListBox", "WM_CTLCOLORLISTBOX"},
{0x135, "WMCtlColorBtn", "WM_CTLCOLORBTN"},
{0x136, "WMCtlColorDlg", "WM_CTLCOLORDLG"},
{0x137, "WMCtlColorScrollBar", "WM_CTLCOLORSCROLLBAR"},
{0x138, "WMCtlColorStatic", "WM_CTLCOLORSTATIC"},
{0x200, "WMMouseMove", "WM_MOUSEMOVE"},
{0x201, "WMLButtonDown", "WM_LBUTTONDOWN"},
{0x202, "WMLButtonUp", "WM_LBUTTONUP"},
{0x203, "WMLButtonDblClk", "WM_LBUTTONDBLCLK"},
{0x204, "WMRButtonDown", "WM_RBUTTONDOWN"},
{0x205, "WMRButtonUp", "WM_RBUTTONUP"},
{0x206, "WMRButtonDblClk", "WM_RBUTTONDBLCLK"},
{0x207, "WMMButtonDown", "WM_MBUTTONDOWN"},
{0x208, "WMMButtonUp", "WM_MBUTTONUP"},
{0x209, "WMMButtonDblClk", "WM_MBUTTONDBLCLK"},
{0x20A, "WMMouseWheel", "WM_MOUSEWHEEL"},
{0x210, "WMParentNotify", "WM_PARENTNOTIFY"},
{0x211, "WMEnterMenuLoop", "WM_ENTERMENULOOP"},
{0x212, "WMExitMenuLoop", "WM_EXITMENULOOP"},
//{0x213, "?", "WM_NEXTMENU"},
//{0x214, "?", "WM_SIZING"},
//{0x215, "?", "WM_CAPTURECHANGED"},
//{0x216, "?", "WM_MOVING"},
//{0x218, "?", "WM_POWERBROADCAST"},
//{0x219, "?", "WM_DEVICECHANGE"},
{0x220, "WMMDICreate", "WM_MDICREATE"},
{0x221, "WMMDIDestroy", "WM_MDIDESTROY"},
{0x222, "WMMDIActivate", "WM_MDIACTIVATE"},
{0x223, "WMMDIRestore", "WM_MDIRESTORE"},
{0x224, "WMMDINext", "WM_MDINEXT"},
{0x225, "WMMDIMaximize", "WM_MDIMAXIMIZE"},
{0x226, "WMMDITile", "WM_MDITILE"},
{0x227, "WMMDICascade", "WM_MDICASCADE"},
{0x228, "WMMDIIconArrange", "WM_MDIICONARRANGE"},
{0x229, "WMMDIGetActive", "WM_MDIGETACTIVE"},
{0x230, "WMMDISetMenu", "WM_MDISETMENU"},
//{0x231, "?", "WM_ENTERSIZEMOVE"},
//{0x232, "?", "WM_EXITSIZEMOVE"},
{0x233, "WMDropFiles", "WM_DROPFILES"},
{0x234, "WMMDIRefreshMenu", "WM_MDIREFRESHMENU"},
//{0x281, "?", "WM_IME_SETCONTEXT"},
//{0x282, "?", "WM_IME_NOTIFY"},
//{0x283, "?", "WM_IME_CONTROL"},
//{0x284, "?", "WM_IME_COMPOSITIONFULL"},
//{0x285, "?", "WM_IME_SELECT"},
//{0x286, "?", "WM_IME_CHAR"},
//{0x288, "?", "WM_IME_REQUEST"},
//{0x290, "?", "WM_IME_KEYDOWN"},
//{0x291, "?", "WM_IME_KEYUP"},
//{0x2A1, "?", "WM_MOUSEHOVER"},
//{0x2A3, "?", "WM_MOUSELEAVE"},
{0x300, "WMCut", "WM_CUT"},
{0x301, "WMCopy", "WM_COPY"},
{0x302, "WMPaste", "WM_PASTE"},
{0x303, "WMClear", "WM_CLEAR"},
{0x304, "WMUndo", "WM_UNDO"},
{0x305, "WMRenderFormat", "WM_RENDERFORMAT"},
{0x306, "WMRenderAllFormats", "WM_RENDERALLFORMATS"},
{0x307, "WMDestroyClipboard", "WM_DESTROYCLIPBOARD"},
{0x308, "WMDrawClipboard", "WM_DRAWCLIPBOARD"},
{0x309, "WMPaintClipboard", "WM_PAINTCLIPBOARD"},
{0x30A, "WMVScrollClipboard", "WM_VSCROLLCLIPBOARD"},
{0x30B, "WMSizeClipboard", "WM_SIZECLIPBOARD"},
{0x30C, "WMAskCBFormatName", "WM_ASKCBFORMATNAME"},
{0x30D, "WMChangeCBChain", "WM_CHANGECBCHAIN"},
{0x30E, "WMHScrollClipboard", "WM_HSCROLLCLIPBOARD"},
{0x30F, "WMQueryNewPalette", "WM_QUERYNEWPALETTE"},
{0x310, "WMPaletteIsChanging", "WM_PALETTEISCHANGING"},
{0x311, "WMPaletteChanged", "WM_PALETTECHANGED"},
{0x312, "WMHotKey", "WM_HOTKEY"},
//{0x317, "?", "WM_PRINT"},
//{0x318, "?", "WM_PRINTCLIENT"},
//{0x358, "?", "WM_HANDHELDFIRST"},
//{0x35F, "?", "WM_HANDHELDLAST"},
//{0x380, "?", "WM_PENWINFIRST"},
//{0x38F, "?", "WM_PENWINLAST"},
//{0x390, "?", "WM_COALESCE_FIRST"},
//{0x39F, "?", "WM_COALESCE_LAST"},
{0x3E0, "WMDDE_Initiate", "WM_DDE_INITIATE"},
{0x3E1, "WMDDE_Terminate", "WM_DDE_TERMINATE"},
{0x3E2, "WMDDE_Advise", "WM_DDE_ADVISE"},
{0x3E3, "WMDDE_UnAdvise", "WM_DDE_UNADVISE"},
{0x3E4, "WMDDE_Ack", "WM_DDE_ACK"},
{0x3E5, "WMDDE_Data", "WM_DDE_DATA"},
{0x3E6, "WMDDE_Request", "WM_DDE_REQUEST"},
{0x3E7, "WMDDE_Poke", "WM_DDE_POKE"},
{0x3E8, "WMDDE_Execute", "WM_DDE_EXECUTE"},
{0, ""}
};

static MsgInfo VCLControlsMsgTab[] =
{
{0xB000, "CMActivate", "CM_ACTIVATE"},
{0xB001, "CMDeactivate", "CM_DEACTIVATE"},
{0xB002, "CMGotFocus", "CM_GOTFOCUS"},
{0xB003, "CMLostFocus", "CM_LOSTFOCUS"},
{0xB004, "CMCancelMode", "CM_CANCELMODE"},
{0xB005, "CMDialogKey", "CM_DIALOGKEY"},
{0xB006, "CMDialogChar", "CM_DIALOGCHAR"},
{0xB007, "CMFocusChenged", "CM_FOCUSCHANGED"},
{0xB008, "CMParentFontChanged", "CM_PARENTFONTCHANGED"},
{0xB009, "CMParentColorChanged", "CM_PARENTCOLORCHANGED"},
{0xB00A, "CMHitTest", "CM_HITTEST"},
{0xB00B, "CMVisibleChanged", "CM_VISIBLECHANGED"},
{0xB00C, "CMEnabledChanged", "CM_ENABLEDCHANGED"},
{0xB00D, "CMColorChanged", "CM_COLORCHANGED"},
{0xB00E, "CMFontChanged", "CM_FONTCHANGED"},
{0xB00F, "CMCursorChanged", "CM_CURSORCHANGED"},
{0xB010, "CMCtl3DChanged", "CM_CTL3DCHANGED"},
{0xB011, "CMParentCtl3DChanged", "CM_PARENTCTL3DCHANGED"},
{0xB012, "CMTextChanged", "CM_TEXTCHANGED"},
{0xB013, "CMMouseEnter", "CM_MOUSEENTER"},
{0xB014, "CMMouseLeave", "CM_MOUSELEAVE"},
{0xB015, "CMMenuChanged", "CM_MENUCHANGED"},
{0xB016, "CMAppKeyDown", "CM_APPKEYDOWN"},
{0xB017, "CMAppSysCommand", "CM_APPSYSCOMMAND"},
{0xB018, "CMButtonPressed", "CM_BUTTONPRESSED"},
{0xB019, "CMShowingChanged", "CM_SHOWINGCHANGED"},
{0xB01A, "CMEnter", "CM_ENTER"},
{0xB01B, "CMExit", "CM_EXIT"},
{0xB01C, "CMDesignHitTest", "CM_DESIGNHITTEST"},
{0xB01D, "CMIconChanged", "CM_ICONCHANGED"},
{0xB01E, "CMWantSpecialKey", "CM_WANTSPECIALKEY"},
{0xB01F, "CMInvokeHelp", "CM_INVOKEHELP"},
{0xB020, "CMWondowHook", "CM_WINDOWHOOK"},
{0xB021, "CMRelease", "CM_RELEASE"},
{0xB022, "CMShowHintChanged", "CM_SHOWHINTCHANGED"},
{0xB023, "CMParentShowHintChanged", "CM_PARENTSHOWHINTCHANGED"},
{0xB024, "CMSysColorChange", "CM_SYSCOLORCHANGE"},
{0xB025, "CMWinIniChange", "CM_WININICHANGE"},
{0xB026, "CMFontChange", "CM_FONTCHANGE"},
{0xB027, "CMTimeChange", "CM_TIMECHANGE"},
{0xB028, "CMTabStopChanged", "CM_TABSTOPCHANGED"},
{0xB029, "CMUIActivate", "CM_UIACTIVATE"},
{0xB02A, "CMUIDeactivate", "CM_UIDEACTIVATE"},
{0xB02B, "CMDocWindowActivate", "CM_DOCWINDOWACTIVATE"},
{0xB02C, "CMControlLIstChange", "CM_CONTROLLISTCHANGE"},
{0xB02D, "CMGetDataLink", "CM_GETDATALINK"},
{0xB02E, "CMChildKey", "CM_CHILDKEY"},
{0xB02F, "CMDrag", "CM_DRAG"},
{0xB030, "CMHintShow", "CM_HINTSHOW"},
{0xB031, "CMDialogHanlde", "CM_DIALOGHANDLE"},
{0xB032, "CMIsToolControl", "CM_ISTOOLCONTROL"},
{0xB033, "CMRecreateWnd", "CM_RECREATEWND"},
{0xB034, "CMInvalidate", "CM_INVALIDATE"},
{0xB035, "CMSysFontChanged", "CM_SYSFONTCHANGED"},
{0xB036, "CMControlChange", "CM_CONTROLCHANGE"},
{0xB037, "CMChanged", "CM_CHANGED"},
{0xB038, "CMDockClient", "CM_DOCKCLIENT"},
{0xB039, "CMUndockClient", "CM_UNDOCKCLIENT"},
{0xB03A, "CMFloat", "CM_FLOAT"},
{0xB03B, "CMBorderChanged", "CM_BORDERCHANGED"},
{0xB03C, "CMBiDiModeChanged", "CM_BIDIMODECHANGED"},
{0xB03D, "CMParentBiDiModeChanged", "CM_PARENTBIDIMODECHANGED"},
{0xB03E, "CMAllChildrenFlipped", "CM_ALLCHILDRENFLIPPED"},
{0xB03F, "CMActionUpdate", "CM_ACTIONUPDATE"},
{0xB040, "CMActionExecute", "CM_ACTIONEXECUTE"},
{0xB041, "CMHintShowPause", "CM_HINTSHOWPAUSE"},
{0xB044, "CMDockNotification", "CM_DOCKNOTIFICATION"},
{0xB043, "CMMouseWheel", "CM_MOUSEWHEEL"},
{0xB044, "CMIsShortcut", "CM_ISSHORTCUT"},
{0xB045, "CMRawX11Event", "CM_RAWX11EVENT"},
{0, "", ""}
};

PMsgMInfo __fastcall GetMsgInfo(WORD msg)
{
    //WindowsMsgTab
    if (msg < 0x400)
    {
        for (int m = 0;; m++)
        {
            if (!WindowsMsgTab[m].id) break;
            if (WindowsMsgTab[m].id == msg) return &WindowsMsgTab[m];
        }
    }
    //VCLControlsMsgTab
    if (msg >= 0xB000 && msg < 0xC000)
    {
        for (int m = 0;; m++)
        {
            if (!VCLControlsMsgTab[m].id) break;
            if (VCLControlsMsgTab[m].id == msg) return &VCLControlsMsgTab[m];
        }
    }
    return 0;
}

//---------------------------------------------------------------------
String __fastcall Guid2String(BYTE* Guid)
{
    int     n;
    char    sbyte[8];
    String  Result = "['{";

    for (int i = 0; i < 16; i++)
    {
        switch (i)
        {
        case 0:
        case 1:
        case 2:
        case 3:
            n = 3 - i;
            break;
        case 4:
            n = 5;
            break;
        case 5:
            n = 4;
            break;
        case 6:
            n = 7;
            break;
        case 7:
            n = 6;
            break;
        default:
            n = i;
            break;
        }
        if (i == 4 || i == 6 || i == 8 || i == 10) Result += '-';
        sprintf(sbyte, "%02X", Guid[n]);
        Result += String(sbyte);
    }
    Result += "}']";
    return Result;
}


//---------------------------------------------------------------------------
void __fastcall ScaleForm(TForm* AForm)
{
    HDC _hdc = GetDC(0);
    if (_hdc)
    {
        AForm->ScaleBy(GetDeviceCaps(_hdc, 0x58), 100);
        ReleaseDC(0, _hdc);
    }
}
//---------------------------------------------------------------------------
LONGLONG __fastcall Adr2Pos(ULONGLONG adr)
{
    LONGLONG     ofs = 0;
    for (int n = 0; n < SegmentList->Count; n++)
    {
        PSegmentInfo segInfo = (PSegmentInfo)SegmentList->Items[n];
        if (adr >= segInfo->Start && adr < segInfo->Start + segInfo->Size)
        {
            if (segInfo->Flags & 0x80000)
                return -1;
            return ofs + (adr - segInfo->Start);
        }
        if (!(segInfo->Flags & 0x80000))
            ofs += segInfo->Size;
    }
    return -2;
}
//---------------------------------------------------------------------------
ULONGLONG __fastcall Pos2Adr(LONGLONG Pos)
{
    LONGLONG     fromPos = 0;
    LONGLONG     toPos = 0;
    for (int n = 0; n < SegmentList->Count; n++)
    {
        PSegmentInfo segInfo = (PSegmentInfo)SegmentList->Items[n];
        if (!(segInfo->Flags & 0x80000))
        {
            fromPos = toPos;
            toPos += segInfo->Size;
            if (fromPos <= Pos && Pos < toPos)
                return segInfo->Start + (Pos - fromPos);
        }
    }
    return 0;
}
//---------------------------------------------------------------------------
//Can replace type "fromName" to type "toName"?
bool __fastcall CanReplace(const String& fromName, const String& toName)
{
	//Skip empty toName
	if (toName == "") return false;
    //We can replace empty "fromName" or name "byte", "word", "dword'
    if (fromName == "" || SameText(fromName, "byte") || SameText(fromName, "word") || SameText(fromName, "dword")) return true;
    return false;
}
//---------------------------------------------------------------------------
String __fastcall GetDefaultProcName(DWORD adr)
{
    return "sub_" + Val2Str8(adr);
}
//---------------------------------------------------------------------------
String __fastcall Val2Str0(DWORD Val)
{
    return IntToHex((int)Val, 0);
}
//---------------------------------------------------------------------------
String __fastcall Val2Str1(DWORD Val)
{
    return IntToHex((int)Val, 1);
}
//---------------------------------------------------------------------------
String __fastcall Val2Str2(DWORD Val)
{
    return IntToHex((int)Val, 2);
}
//---------------------------------------------------------------------------
String __fastcall Val2Str4(DWORD Val)
{
    return IntToHex((int)Val, 4);
}
//---------------------------------------------------------------------------
String __fastcall Val2Str5(DWORD Val)
{
    return IntToHex((int)Val, 5);
}
//---------------------------------------------------------------------------
String __fastcall Val2Str8(DWORD Val)
{
    return IntToHex((int)Val, 8);
}
//---------------------------------------------------------------------------
PInfoRec Idr64Manager::AddToBSSInfos(DWORD Adr, String AName, String ATypeName)
{
    PInfoRec recN;
    String _key = Val2Str8(Adr);
    int _idx = BSSInfos->IndexOf(_key);
    if (_idx == -1)
    {
        recN = new InfoRec(-1, ikData);
        recN->SetName(AName);
        recN->type = ATypeName;
        BSSInfos->AddObject(_key, (TObject*)recN);
    }
    else
    {
        recN = (PInfoRec)BSSInfos->Objects[_idx];
        if (recN->type == "")
        {
            recN->type = ATypeName;
        }
    }
    return recN;
}
void Idr64Manager::BSSInfosAddObject(String _adr, PInfoRec recN)
{
    BSSInfos->AddObject(_adr, (TObject*)recN);
}

PInfoRec Idr64Manager::GetBSSInfosRec(const String s)
{
    PInfoRec recN = 0;
    int _idx = BSSInfos->IndexOf(s);
    if (_idx != -1)
    {
        recN = GetBSSInfosObject(_idx);
    }
    return recN;
}

//---------------------------------------------------------------------------
String __fastcall MakeGvarName(DWORD adr)
{
    return "gvar_" + Val2Str8(adr);
}
//---------------------------------------------------------------------------
void __fastcall MakeGvar(PInfoRec recN, DWORD adr, DWORD xrefAdr)
{
    if (!recN->HasName()) recN->SetName(MakeGvarName(adr));
    if (xrefAdr) recN->AddXref('C', xrefAdr, 0);
}
//---------------------------------------------------------------------------
void __fastcall FillArgInfo(int k, BYTE callkind, PARGINFO argInfo, BYTE** p, int* s)
{
    BYTE* pp = *p; int ss = *s;
    argInfo->Tag = *pp; pp++;
    int locflags = *((int*)pp); pp += 4;

    if ((locflags & 7) == 1) argInfo->Tag = 0x23; //Add by ZGL

    argInfo->Register = (locflags & 8);
    int ndx = *((int*)pp); pp += 4;

    //fastcall
    if (!callkind)
    {
        if (argInfo->Register && k < 4) //ECX,EDX,R8,R9
        {
            argInfo->Ndx = k;
        }
        else
        {
            argInfo->Ndx = ndx;
        }
    }
    //stdcall, cdecl, pascal
    else
    {
        argInfo->Ndx = ss;
        ss += 4;
    }

    argInfo->Size = 4;
    WORD wlen = *((WORD*)pp); pp += 2;
    argInfo->Name = String((char*)pp, wlen); pp += wlen + 1;
    wlen = *((WORD*)pp); pp += 2;
    argInfo->TypeDef = TrimTypeName(String((char*)pp, wlen)); pp += wlen + 1;
    *p = pp; *s = ss;
}
//---------------------------------------------------------------------------
String __fastcall TrimTypeName(const String& TypeName)
{
    if (TypeName.IsEmpty())
        return TypeName;
    int pos = TypeName.Pos(".");
    //No '.' in TypeName or TypeName begins with '.'
    if (pos == 0 || pos == 1)
        return TypeName;
    //или это имя типа range
    else if (TypeName[pos + 1] == '.')
        return TypeName;
    else
    {
        char c, *p = TypeName.c_str();
        //Check special symbols upto '.'
        while (1)
        {
            c = *p++;
            if (c == '.') break;
            if (c < '0' || c == '<')
                return TypeName;
        }
        return ExtractProcName(TypeName);
    }
}
//---------------------------------------------------------------------------
bool __fastcall IsValidImageAdr(ULONGLONG Adr)
{
    if (Adr >= CodeBase && Adr < CodeBase + ImageSize)
        return true;
    else
        return false;
}
//---------------------------------------------------------------------------
bool __fastcall IsValidCodeAdr(DWORD Adr)
{
    if (Adr >= CodeBase && Adr < CodeBase + CodeSize)
        return true;
    else
        return false;
}
//---------------------------------------------------------------------------
String __fastcall ExtractClassName(const String& AName)
{
    if (AName == "") return "";
    int pos = AName.Pos(".");
    if (pos)
        return AName.SubString(1, pos - 1);
    else
        return "";
}
//---------------------------------------------------------------------------
String __fastcall ExtractProcName(const String& AName)
{
    if (AName == "") return "";
    int pos = AName.Pos(".");
    if (pos)
        return AName.SubString(pos + 1, AName.Length());
    else
        return AName;
}
//---------------------------------------------------------------------------
String __fastcall ExtractName(const String& AName)
{
    if (AName == "") return "";
    int _pos = AName.Pos(":");
    if (_pos)
        return AName.SubString(1, _pos - 1);
    else
        return AName;
}
//---------------------------------------------------------------------------
String __fastcall ExtractType(const String& AName)
{
    if (AName == "") return "";
    int _pos = AName.Pos(":");
    if (_pos)
        return AName.SubString(_pos + 1, AName.Length());
    else
        return "";
}
//---------------------------------------------------------------------------
//Return position of nearest up argument rcx (ecx, ch, cl) from position fromPos
int __fastcall Idr64Manager::GetNearestArgC(int fromPos)
{
    int         curPos = fromPos;

    for (curPos = fromPos - 1;;curPos--)
    {
        if (idr.IsFlagSet(cfInstruction, curPos))
        {
            if (IsFlagSet(cfProcStart, curPos)) break;
            if (IsFlagSet(cfSetC, curPos)) return curPos;
        }
    }
    return -1;
}
//---------------------------------------------------------------------------
//Return position of nearest up instruction with segment prefix fs:
int __fastcall Idr64Manager::GetNearestUpPrefixFs(int fromPos)
{
    int         _pos;
    DISINFO     _disInfo;

    assert(fromPos >= 0);
    for (_pos = fromPos - 1; _pos >= 0; _pos--)
    {
        if (IsFlagSet(cfInstruction, _pos))
        {
            GetDisasm().Disassemble(Code + _pos, Pos2Adr(_pos), &_disInfo, 0);
            if (_disInfo.SegPrefix == 4) return _pos;
        }
        if (IsFlagSet(cfProcStart, _pos)) break;
    }
    return -1;
}
//---------------------------------------------------------------------------
//Return position of nearest up instruction from position fromPos
int __fastcall Idr64Manager::GetNearestUpInstruction(int fromPos)
{
    assert(fromPos >= 0);
    for (int pos = fromPos - 1; pos >= 0; pos--)
    {
        if (IsFlagSet(cfInstruction, pos)) return pos;
        if (IsFlagSet(cfProcStart, pos)) break;
    }
    return -1;
}
//---------------------------------------------------------------------------
//Return position of N-th up instruction from position fromPos
int __fastcall Idr64Manager::GetNthUpInstruction(int fromPos, int N)
{
if (fromPos < 0)
return -1;
    assert(fromPos >= 0);
    for (int pos = fromPos - 1; pos >= 0; pos--)
    {
        if (IsFlagSet(cfInstruction, pos))
        {
            N--;
            if (!N) return pos;
        }
        if (IsFlagSet(cfProcStart, pos)) break;
    }
    return -1;
}
//---------------------------------------------------------------------------
//Return position of nearest up instruction from position fromPos
int __fastcall Idr64Manager::GetNearestUpInstruction(int fromPos, int toPos)
{
    assert(fromPos >= 0);
    for (int pos = fromPos - 1; pos >= toPos; pos--)
    {
        if (IsFlagSet(cfInstruction, pos)) return pos;
        if (IsFlagSet(cfProcStart, pos)) break;
    }
    return -1;
}
//---------------------------------------------------------------------------
int __fastcall Idr64Manager::GetNearestUpInstruction(int fromPos, int toPos, int no)
{
    assert(fromPos >= 0);
    for (int pos = fromPos - 1; pos >= toPos; pos--)
    {
        if (IsFlagSet(cfInstruction, pos))
        {
            no--;
            if (!no) return pos;
        }
    }
    return -1;
}
//---------------------------------------------------------------------------
//Return position of nearest up instruction from position fromPos
int __fastcall Idr64Manager::GetNearestUpInstruction1(int fromPos, int toPos, String Instruction)
{
    int         len = Instruction.Length();
    int         pos;
    DISINFO     DisInfo;

    assert(fromPos >= 0);
    for (pos = fromPos - 1; pos >= toPos; pos--)
    {
        if (IsFlagSet(cfInstruction, pos))
        {
            GetDisasm().Disassemble(Code + pos, Pos2Adr(pos), &DisInfo, 0);
            if (len && SameText(GetDisasm().GetMnemonic(DisInfo.MnemIdx), Instruction)) return pos;
        }
        if (IsFlagSet(cfProcStart, pos)) break;
    }
    return -1;
}
//---------------------------------------------------------------------------
//Return position of nearest up instruction from position fromPos
int __fastcall Idr64Manager::GetNearestUpInstruction2(int fromPos, int toPos, String Instruction1, String Instruction2)
{
    int         len1 = Instruction1.Length(), len2 = Instruction2.Length();
    int         pos;
    DISINFO     DisInfo;

    assert(fromPos >= 0);
    for (pos = fromPos - 1; pos >= toPos; pos--)
    {
        if (IsFlagSet(cfInstruction, pos))
        {
            GetDisasm().Disassemble(Code + pos, Pos2Adr(pos), &DisInfo, 0);
            if ((len1 && SameText(GetDisasm().GetMnemonic(DisInfo.MnemIdx), Instruction1)) ||
                (len2 && SameText(GetDisasm().GetMnemonic(DisInfo.MnemIdx), Instruction2))) return pos;
        }
        if (IsFlagSet(cfProcStart, pos)) break;
    }
    return -1;
}
//---------------------------------------------------------------------------
//Return position of nearest down instruction from position fromPos
int __fastcall Idr64Manager::GetNearestDownInstruction(int fromPos)
{
    int         instrLen;
    DISINFO     DisInfo;

    assert(fromPos >= 0);
    instrLen = GetDisasm().Disassemble(Code + fromPos, Pos2Adr(fromPos), &DisInfo, 0);
    if (!instrLen) return -1;
    return fromPos + instrLen;
}
//---------------------------------------------------------------------------
//Return position of nearest down "Instruction" from position fromPos
int __fastcall Idr64Manager::GetNearestDownInstruction(int fromPos, String Instruction)
{
    int         instrLen, len = Instruction.Length();
    int         curPos = fromPos;
    DISINFO     DisInfo;

    assert(fromPos >= 0);
    while (1)
    {
        instrLen = GetDisasm().Disassemble(Code + curPos, Pos2Adr(curPos), &DisInfo, 0);
        if (!instrLen)
        {
            curPos++;
            continue;
        }
        if (len && SameText(GetDisasm().GetMnemonic(DisInfo.MnemIdx), Instruction)) return curPos + instrLen;
        if (DisInfo.Ret) break;
        curPos += instrLen;
    }
    return -1;
}
//---------------------------------------------------------------------------
//-1 - error
//0 - simple if
//1 - jcc down
//2 - jcc up
//3 - jmp down
//4 - jump up
int __fastcall Idr64Manager::BranchGetPrevInstructionType(DWORD fromAdr, DWORD* jmpAdr, PLoopInfo loopInfo)
{
    int         _pos;
    DISINFO     _disInfo;

    *jmpAdr = 0;
    _pos = GetNearestUpInstruction(Adr2Pos(fromAdr));
    if (_pos == -1) return -1;
    GetDisasm().Disassemble(Code + _pos, Pos2Adr(_pos), &_disInfo, 0);
    if (_disInfo.Branch)
    {
        if (IsExit(_disInfo.Immediate)) return 0;
        if (_disInfo.Conditional)
        {
            if (_disInfo.Immediate > CodeBase + _pos)
            {
                if (loopInfo && loopInfo->BreakAdr == _disInfo.Immediate) return 0;
                return 1;
            }
            return 2;
        }
        if (_disInfo.Immediate > CodeBase + _pos)
        {
            *jmpAdr = _disInfo.Immediate;
            return 3;
        }
        return 4;
    }
    return 0;
}
//---------------------------------------------------------------------------
//pInfo must contain pInfo->
int __fastcall GetProcRetBytes(MProcInfo* pInfo)
{
    int     _pos = pInfo->DumpSz - 1;
    DWORD   _curAdr = CodeBase + _pos;
    DISINFO _disInfo;

    while (_pos >= 0)
    {
        GetDisasm().Disassemble(pInfo->Dump + _pos, (__int64)_curAdr, &_disInfo, 0);
        if (_disInfo.Ret)
        {
            if (_disInfo.OpType[0] == otIMM)//ImmPresent)
                return _disInfo.Immediate;
            else
                return 0;
        }
        _pos--; _curAdr--;
    }
    return 0;
}
//---------------------------------------------------------------------------
int __fastcall GetProcSize(DWORD fromAdr)
{
    int     _size = 0;
    PInfoRec recN = GetInfoRec(fromAdr);
    if (recN && recN->procInfo) _size = recN->procInfo->procSize;
    if (!_size) _size = EstimateProcSize(fromAdr);
    return _size;
}
//---------------------------------------------------------------------------
String __fastcall GetDecompilerRegisterName(int Idx)
{
    assert(Idx >= 0 && Idx < 32);
    if (Idx >= 16) Idx -= 16;
    else if (Idx >= 8) Idx -= 8;
    return UpperCase(GetDisasm().GetrgszReg32(Idx));
}
//---------------------------------------------------------------------------
bool __fastcall IsValidModuleName(int len, int pos)
{
    if (!len) return false;
    for (int i = pos; i < pos + len; i++)
    {
        BYTE b = *(Code + i);
        if (b < ' ' || b == ':' || (b & 0x80)) return false;
    }
    return true;
}
//---------------------------------------------------------------------------
bool __fastcall IsValidName(int len, int pos)
{
    if (!len) return false;
    for (int i = pos; i < pos + len; i++)
    {
        //if (IsFlagSet(cfCode, i)) return false;

        BYTE b = *(Code + i);
        //first symbol may be letter or '_' or '.' or ':'
        if (i == pos)
        {
            if ((b >= 'A' && b <= 'z') || b == '.' || b == '_' || b == ':')
                continue;
            else
                return false;
        }
        if (b & 0x80) return false;
        //if ((b < '0' || b > 'z') && b != '.' && b != '_' && b != ':' && b != '$') return false;
    }
    return true;
}
//---------------------------------------------------------------------------
bool __fastcall IsValidString(int len, int pos)
{
    if (len < 5) return false;
    for (int i = pos; i < pos + len; i++)
    {
        //if (IsFlagSet(cfCode, i)) return false;

        BYTE b = *(Code + i);
        if (b < ' ' && b != '\t' && b != '\n' && b != '\r') return false;
    }
    return true;
}
//---------------------------------------------------------------------------
bool __fastcall IsValidCString(int pos)
{
    int len = 0;
    for (int i = pos; i < pos + 1024; i++)
    {
        BYTE b = *(Code + i);
        //if (IsFlagSet(cfCode, i)) break;
        if (!b) return (len >= 5);
        if (b < ' ' && b != '\t' && b != '\n' && b != '\r') break;
        len++;
    }           
    return false;
}
//---------------------------------------------------------------------------
DWORD __fastcall GetParentAdr(DWORD Adr)
{
    if (!IsValidImageAdr(Adr)) return 0;

    DWORD vmtAdr = Adr - Vmt.SelfPtr;
    DWORD pos = Adr2Pos(vmtAdr) + Vmt.Parent;
    DWORD adr = *((DWORD*)(Code + pos));
    if (IsValidImageAdr(adr) && idr.IsFlagSet(cfImport, Adr2Pos(adr)))
        return 0;
    return adr;
}
//---------------------------------------------------------------------------
DWORD __fastcall GetChildAdr(DWORD Adr)
{
    if (!IsValidImageAdr(Adr)) return 0;
    for (int m = 0; m < VmtList->Count; m++)
    {
        PVmtListRec recV = (PVmtListRec)VmtList->Items[m];
        if (recV->vmtAdr != Adr && IsInheritsByAdr(recV->vmtAdr, Adr))
            return recV->vmtAdr;
    }
    return 0;
}
//---------------------------------------------------------------------------
int __fastcall GetClassSize(DWORD adr)
{
    if (!IsValidImageAdr(adr)) return 0;

    DWORD vmtAdr = adr - Vmt.SelfPtr;
    DWORD pos = Adr2Pos(vmtAdr) + Vmt.InstanceSize;
    int size = *((int*)(Code + pos));
    return size - 4;
}
//---------------------------------------------------------------------------
String __fastcall GetClsName(DWORD adr)
{
    if (!IsValidImageAdr(adr)) return "";

    DWORD vmtAdr = adr - Vmt.SelfPtr;
    DWORD pos = Adr2Pos(vmtAdr) + Vmt.ClassName;
    if (idr.IsFlagSet(cfImport, pos))
    {
        PInfoRec recN = GetInfoRec(vmtAdr + Vmt.ClassName);
        return recN->GetName();
    }
    DWORD nameAdr = *((DWORD*)(Code + pos));
    if (!IsValidImageAdr(nameAdr))
        return "";

    pos = Adr2Pos(nameAdr);
    BYTE len = Code[pos]; pos++;
    return String((char*)&Code[pos], len);
}
//---------------------------------------------------------------------------
DWORD __fastcall GetClassAdr(const String& AName)
{
    String      name;

    if (AName.IsEmpty()) return 0;

    DWORD adr = FindClassAdrByName(AName);
    if (adr) return adr;

    int pos = AName.Pos(".");
    if (pos)
    {
        //type as .XX or array[XX..XX] of XXX - skip
        if (pos == 1 || AName[pos + 1] == '.') return 0;
        name = AName.SubString(pos + 1, AName.Length());
    }
    else
        name = AName;

    const int vmtCnt = VmtList->Count;
    for (int n = 0; n < vmtCnt; n++)
    {
        PVmtListRec recV = (PVmtListRec)VmtList->Items[n];
        if (SameText(recV->vmtName, name))
        {
            adr = recV->vmtAdr;
            AddClassAdr(adr, name);
            return adr;
        }
    }
    return 0;
}

//---------------------------------------------------------------------------
int __fastcall GetParentSize(DWORD Adr)
{
    return GetClassSize(GetParentAdr(Adr));
}
//---------------------------------------------------------------------------
String __fastcall GetParentName(DWORD Adr)
{
    DWORD adr = GetParentAdr(Adr);
    if (!adr) return "";
    return GetClsName(adr);
}
//---------------------------------------------------------------------------
String __fastcall GetParentName(const String& ClassName)
{
	return GetParentName(GetClassAdr(ClassName));
}
//---------------------------------------------------------------------------
//Adr1 inherits Adr2 (Adr1 >= Adr2)
bool __fastcall IsInheritsByAdr(const DWORD Adr1, const DWORD Adr2)
{
    DWORD adr = Adr1;
    while (adr)
    {
        if (adr == Adr2) return true;
        adr = GetParentAdr(adr);
    }
    return false;
}
//---------------------------------------------------------------------------
//Name1 >= Name2
bool __fastcall IsInheritsByClassName(const String& Name1, const String& Name2)
{
    DWORD adr = GetClassAdr(Name1);
    while (adr)
    {
        if (SameText(GetClsName(adr), Name2)) return true;
        adr = GetParentAdr(adr);
    }
    return false;
}
//---------------------------------------------------------------------------
bool __fastcall IsInheritsByProcName(const String& Name1, const String& Name2)
{
    return (IsInheritsByClassName(ExtractClassName(Name1), ExtractClassName(Name2)) &&
            SameText(ExtractProcName(Name1), ExtractProcName(Name2)));
}
//---------------------------------------------------------------------------
String __fastcall TransformString(char* str, int len)
{
    bool        s = true;//true - print string, false - print #XX
    BYTE        c, *p = str;
    String      res = "";

    for (int k = 0; k < len; k++)
    {
        c = *p; p++;
        if (!(c & 0x80) && c <= 13)
        {
            if (s)
            {
                if (k) res += "'+";
            }
            else
                res += "+";
            res += "#" + String((int)c);
            s = false;
        }
        else
        {
            if (s)
            {
                if (!k) res += "'";
            }
            else
                res += "+";
            s = true;
        }
        if (c == 0x22)
            res += "\"";
        else if (c == 0x27)
            res += "'";
        else if (c == 0x5C)
            res += "\\";
        else if (c > 13)
            res += (char)c;
    }
    if (s) res += "'";
    return res;
}
//---------------------------------------------------------------------------
String __fastcall TransformUString(WORD codePage, wchar_t* data, int len)
{
    if (!IsValidCodePage(codePage)) codePage = CP_ACP;
    int nChars = WideCharToMultiByte(codePage, 0, data, -1, 0, 0, 0, 0);
    if (!nChars) return "";
    char* tmpBuf = new char[nChars + 1];
    WideCharToMultiByte(codePage, 0, data, -1, tmpBuf, nChars, 0, 0);
    tmpBuf[nChars] = 0;
    String res = QuotedStr(tmpBuf);
    delete[] tmpBuf;
    return res;
}
//---------------------------------------------------------------------------
//Get stop address for analyzing virtual tables
DWORD __fastcall GetStopAt(DWORD VmtAdr)
{
    int     m;
    DWORD   pos, pointer, stopAt = CodeBase + TotalSize;

    pos = Adr2Pos(VmtAdr) + Vmt.IntfTable;
    for (m = Vmt.IntfTable; m != Vmt.InstanceSize; m += 8, pos += 8)
    {
        pointer = *((ULONGLONG*)(Code + pos));
        if (pointer >= VmtAdr && pointer < stopAt) stopAt = pointer;
    }
    return stopAt;
}
//---------------------------------------------------------------------------
String __fastcall GetTypeName(DWORD adr)
{
	if (!IsValidImageAdr(adr)) return "?";
    if (idr.IsFlagSet(cfImport, Adr2Pos(adr)))
    {
        PInfoRec recN = GetInfoRec(adr);
        return recN->GetName();
    }
    
    int pos = Adr2Pos(adr);
    if (idr.IsFlagSet(cfRTTI, pos))
        pos += 8;
    //TypeKind
    BYTE kind = *(Code + pos); pos++;
    BYTE len = *(Code + pos); pos++;
    String Result = String((char*)(Code + pos), len);
    if (Result[1] == '.')
    {
        PUnitRec recU = GetUnit(adr);
        if (recU)
        {
            String prefix;
            switch (kind)
            {
            case ikEnumeration:
                prefix = "_Enum_";
                break;
            case ikArray:
                prefix = "_Arr_";
                break;
            case ikDynArray:
                prefix = "_DynArr_";
                break;
            default:
                prefix = GetUnitName(recU);
                break;
            }
            Result = prefix + String((int)recU->iniOrder) + "_" + Result.SubString(2, len);
        }
    }
    return Result;
}
//---------------------------------------------------------------------------
String __fastcall GetDynaInfo(DWORD adr, WORD id, DWORD* dynAdr)
{
	int			m;
	DWORD		classAdr = adr;
    PInfoRec 	recN;
    PMethodRec 	recM;

    *dynAdr = 0;

	if (!IsValidCodeAdr(adr)) return "";

    while (classAdr)
    {
    	recN = GetInfoRec(classAdr);
        if (recN && recN->vmtInfo && recN->vmtInfo->methods)
        {
        	for (m = 0; m < recN->vmtInfo->methods->Count; m++)
            {
            	PMethodRec recM = (PMethodRec)recN->vmtInfo->methods->Items[m];
                if (recM->kind == 'D' && recM->id == id)
                {
                	*dynAdr = recM->address;
                	if (recM->name != "") return recM->name;
                	return "";//GetDefaultProcName(recM->address);
                }
            }
        }
        classAdr = GetParentAdr(classAdr);
    }
    return "";
}
//---------------------------------------------------------------------------
String __fastcall GetDynArrayTypeName(DWORD adr)
{
    Byte    len;
    int     pos;

    pos = Adr2Pos(adr);
    pos += 4;
    pos++;//Kind
    len = Code[pos]; pos++;
    pos += len;//Name
    pos += 4;//elSize
    return GetTypeName(*((DWORD*)(Code + pos)));
}
//---------------------------------------------------------------------------
int __fastcall GetTypeSize(String AName)
{
    int         idx = -1;
    WORD*       uses;
    MTypeInfo   tInfo;

    uses = KnowledgeBase.GetTypeUses(AName.c_str());
    idx = KnowledgeBase.GetTypeIdxByModuleIds(uses, AName.c_str());
    if (uses) delete[] uses;

    if (idx != -1)
    {
        idx = KnowledgeBase.TypeOffsets[idx].NamId;
        if (KnowledgeBase.GetTypeInfo(idx, INFO_DUMP, &tInfo))
        {
            if (tInfo.Size) return tInfo.Size;
        }
    }
    return 4;
}
//---------------------------------------------------------------------------
String TypeKinds[] =
{
    "Unknown",
    "Integer",
    "Char",
    "Enumeration",
    "Float",
    "ShortString",
    "Set",
    "Class",
    "Method",
    "WChar",
    "AnsiString",
    "WideString",
    "Variant",
    "Array",
    "Record",
    "Interface",
    "Int64",
    "DynArray",
    "UString",
    "ClassRef",
    "Pointer",
    "Procedure"
};
//---------------------------------------------------------------------------
String __fastcall TypeKind2Name(BYTE kind)
{
    if (kind < ARRAYSIZE(TypeKinds)) return TypeKinds[kind];
    else return "";
}
//---------------------------------------------------------------------------
DWORD __fastcall GetOwnTypeAdr(String AName)
{
    if (AName == "") return 0;
    PTypeRec recT = GetOwnTypeByName(AName);
    if (recT) return recT->adr;
    return 0;
}
//---------------------------------------------------------------------------
PTypeRec __fastcall GetOwnTypeByName(String AName)
{
    if (AName == "") return 0;
    for (int m = 0; m < OwnTypeList->Count; m++)
    {
        PTypeRec recT = (PTypeRec)OwnTypeList->Items[m];
        if (SameText(recT->name, AName)) return recT;
    }
    return 0;
}
//---------------------------------------------------------------------------
String __fastcall GetTypeDeref(String ATypeName)
{
    int         idx = -1;
    WORD*       uses;
    MTypeInfo   tInfo;

    if (ATypeName[1] == '^') return ATypeName.SubString(2, ATypeName.Length());

    //Scan knowledgeBase
    uses = KnowledgeBase.GetTypeUses(ATypeName.c_str());
    idx = KnowledgeBase.GetTypeIdxByModuleIds(uses, ATypeName.c_str());
    if (uses) delete[] uses;

    if (idx != -1)
    {
        idx = KnowledgeBase.TypeOffsets[idx].NamId;
        if (KnowledgeBase.GetTypeInfo(idx, INFO_DUMP, &tInfo))
        {
            if (tInfo.Decl != "" && tInfo.Decl[1] == '^')
                return tInfo.Decl.SubString(2, tInfo.Decl.Length());
        }
    }
    return "";
}
//---------------------------------------------------------------------------
BYTE __fastcall GetTypeKind(String AName, int* size)
{
    BYTE        res;
    int         pos, idx = -1, kind;
    WORD*       uses;
    MTypeInfo   tInfo;
    String      name, typeName, str;

    *size = 4;
    if (AName != "")
    {
        if (AName.Pos("array"))
        {
            if (AName.Pos("array of")) return ikDynArray;
            return ikArray;
        }

        pos = AName.Pos(".");
        if (pos > 1 && AName[pos + 1] != ':')
            name = AName.SubString(pos + 1, AName.Length());
        else
            name = AName;

        if (SameText(name, "Boolean") ||
            SameText(name, "ByteBool") ||
            SameText(name, "WordBool") ||
            SameText(name, "LongBool"))
        {
            return ikEnumeration;
        }
        if (SameText(name, "ShortInt") ||
            SameText(name, "Byte")     ||
            SameText(name, "SmallInt") ||
            SameText(name, "Word")     ||
            SameText(name, "Dword")    ||
            SameText(name, "Integer")  ||
            SameText(name, "LongInt")  ||
            SameText(name, "LongWord") ||
            SameText(name, "Cardinal"))
        {
            return ikInteger;
        }
        if (SameText(name, "Char"))
        {
            return ikChar;
        }
        if (SameText(name, "Text") || SameText(name, "File"))
        {
            return ikRecord;
        }

        if (SameText(name, "Int64"))
        {
            *size = 8;
            return ikInt64;
        }
        if (SameText(name, "Single"))
        {
            return ikFloat;
        }
        if (SameText(name, "Real48")   ||
            SameText(name, "Real")     ||
            SameText(name, "Double")   ||
            SameText(name, "TDate")    ||
            SameText(name, "TTime")    ||
            SameText(name, "TDateTime")||
            SameText(name, "Comp")     ||
            SameText(name, "Currency"))
        {
            *size = 8;
            return ikFloat;
        }
        if (SameText(name, "Extended"))
        {
            *size = 12;
            return ikFloat;
        }
        if (SameText(name, "ShortString")) return ikString;
        if (SameText(name, "String") || SameText(name, "AnsiString")) return ikLString;
        if (SameText(name, "WideString")) return ikWString;
        if (SameText(name, "UnicodeString") || SameText(name, "UString")) return ikUString;
        if (SameText(name, "PChar") || SameText(name, "PAnsiChar")) return ikCString;
        if (SameText(name, "PWideChar")) return ikWCString;
        if (SameText(name, "Variant")) return ikVariant;
        if (SameText(name, "Pointer")) return ikPointer;

        //File
        String recFileName = idr.WrkDir + "\\types.idr";
        FILE* recFile = fopen(recFileName.c_str(), "rt");
        if (recFile)
        {
            char StringBuf1[2*1024];
            while (1)
            {
                if (!fgets(StringBuf1, 1024, recFile)) break;
                str = String(StringBuf1);
                if (str.Pos(AName + "=") == 1)
                {
                    if (str.Pos("=record"))
                    {
                        fclose(recFile);
                        return ikRecord;
                    }
                }
            }
            fclose(recFile);
        }
        //RTTI
        PTypeRec recT = GetOwnTypeByName(name);
        if (recT)
        {
            *size = 4;
            return recT->kind;
        }
        //Scan KB
        uses = KnowledgeBase.GetTypeUses(name.c_str());
        idx = KnowledgeBase.GetTypeIdxByModuleIds(uses, name.c_str());
        if (uses) delete[] uses;

        if (idx != -1)
        {
            idx = KnowledgeBase.TypeOffsets[idx].NamId;
            if (KnowledgeBase.GetTypeInfo(idx, INFO_DUMP, &tInfo))
            {
                if (tInfo.Kind == 'Z')  //drAlias???
                    return ikUnknown;
                if (tInfo.Decl != "" && tInfo.Decl[1] == '^')
                {
                    return ikUnknown;
                    //res = GetTypeKind(tInfo.Decl.SubString(2, tInfo.Decl.Length()), size);
                    //if (res) return res;
                    //return 0;
                }
                *size = tInfo.Size;
                switch (tInfo.Kind)
                {
                case drRangeDef://0x44
                    return ikEnumeration;
                case drPtrDef://0x45
                    return ikMethod;
                case drProcTypeDef://0x48
                    return ikMethod;
                case drSetDef://0x4A
                    return ikSet;
                case drRecDef://0x4D
                    return ikRecord;
                }
                if (tInfo.Decl != "")
                {
                    res = GetTypeKind(tInfo.Decl, size);
                    if (res) return res;
                }
            }
        }
        //May be Interface name
        if (AName[1] == 'I')
        {
            AName[1] = 'T';
            if (GetTypeKind(AName, size) == ikVMT) return ikInterface;
        }
        //Manual
    }
    return 0;
}
//---------------------------------------------------------------------------
/* Not used?
int __fastcall GetPackedTypeSize(String AName)
{
    int     _size;
    if (SameText(AName, "Boolean")  ||
        SameText(AName, "ShortInt") ||
        SameText(AName, "Byte")     ||
        SameText(AName, "Char"))
    {
        return 1;
    }
    if (SameText(AName, "SmallInt") ||
        SameText(AName, "Word"))
    {
        return 2;
    }
    if (SameText(AName, "Dword")    ||
        SameText(AName, "Integer")  ||
        SameText(AName, "LongInt")  ||
        SameText(AName, "LongWord") ||
        SameText(AName, "Cardinal") ||
        SameText(AName, "Single"))
    {
        return 4;
    }
    if (SameText(AName, "Real48"))
    {
        return 6;
    }
    if (SameText(AName, "Real")     ||
        SameText(AName, "Double")   ||
        SameText(AName, "Comp")     ||
        SameText(AName, "Currency") ||
        SameText(AName, "Int64"))
    {
        return 8;
    }
    if (SameText(AName, "Extended"))
    {
        return 10;
    }
    if (GetTypeKind(AName, &_size) == ikRecord)
    {
        return GetRecordSize(AName);
    }
    return 4;
}
*/
//---------------------------------------------------------------------------
//return string representation of immediate value with comment
String __fastcall GetImmString(int Val)
{
    if (Val > -16 && Val < 16) return String((int)Val);
    return String("$") + Val2Str0(Val);
}
//---------------------------------------------------------------------------
String __fastcall GetImmString(String TypeName, int Val)
{
    int     _size;
    String  _str, _default = GetImmString(Val);
    BYTE _kind = GetTypeKind(TypeName, &_size);
    if (!Val && (_kind == ikString || _kind == ikLString || _kind == ikWString || _kind == ikUString)) return "''";
    if (!Val && (_kind == ikClass || _kind == ikVMT)) return "Nil";
    if (_kind == ikEnumeration)
    {
        _str = GetEnumerationString(TypeName, Val);
        if (_str != "") return _str;
        return _default;
    }
    if (_kind == ikChar) return Format("'%s'", ARRAYOFCONST(((Char)Val)));
    return _default;
}
//---------------------------------------------------------------------------
PInfoRec __fastcall GetInfoRec(DWORD adr)
{
    int pos = Adr2Pos(adr);
    if (pos >= 0)
        return idr.GetInfosAt(pos);

    return idr.GetBSSInfosRec(Val2Str8(adr));
}
//---------------------------------------------------------------------------
String __fastcall GetEnumerationString(String TypeName, Variant Val)
{
    BYTE        len;
    int         n, pos, _val, idx;
    DWORD       adr, typeAdr, minValue, maxValue, minValueB, maxValueB;
    char        *p, *b, *e;
    WORD        *uses;
    MTypeInfo   tInfo;
    String      clsName;

    if (Val.Type() == varString) return String(Val);

    _val = Val;

    if (SameText(TypeName, "Boolean")  ||
        SameText(TypeName, "ByteBool") ||
        SameText(TypeName, "WordBool") ||
        SameText(TypeName, "LongBool"))
    {
        if (_val)
            return "True";
        else
            return "False";
    }

    adr = GetOwnTypeAdr(TypeName);
    //RTTI exists
    if (IsValidImageAdr(adr))
    {
        pos = Adr2Pos(adr);
        pos += 4;
        //typeKind
        pos++;
        len = Code[pos]; pos++;
        clsName = String((char*)(Code + pos), len); pos += len;
        //ordType
        pos++;
        minValue = *((DWORD*)(Code + pos)); pos += 4;
        maxValue = *((DWORD*)(Code + pos)); pos += 4;
        //BaseTypeAdr
        typeAdr = *((DWORD*)(Code + pos)); pos += 4;

        //If BaseTypeAdr != SelfAdr then fields extracted from BaseType
        if (typeAdr != adr)
        {
            pos = Adr2Pos(typeAdr);
            pos += 4;   //SelfPointer
            pos++;      //typeKind
            len = Code[pos]; pos++;
            pos += len; //BaseClassName
            pos++;      //ordType
            minValueB = *((DWORD*)(Code + pos)); pos += 4;
            maxValueB = *((DWORD*)(Code + pos)); pos += 4;
            pos += 4;   //BaseClassPtr
        }
        else
        {
            minValueB = minValue;
            maxValueB = maxValue;
        }

        for (n = minValueB; n <= maxValueB; n++)
        {
            len = Code[pos]; pos++;
            if (n >= minValue && n <= maxValue && n == _val)
            {
                return String((char*)(Code + pos), len);
            }
            pos += len;
        }
    }
    //Try get from KB
    else
    {
        uses = KnowledgeBase.GetTypeUses(TypeName.c_str());
        idx = KnowledgeBase.GetTypeIdxByModuleIds(uses, TypeName.c_str());
        if (uses) delete[] uses;

        if (idx != -1)
        {
            idx = KnowledgeBase.TypeOffsets[idx].NamId;
            if (KnowledgeBase.GetTypeInfo(idx, INFO_FIELDS | INFO_PROPS | INFO_METHODS | INFO_DUMP, &tInfo))
            {
                if (tInfo.Kind == drRangeDef)
                    return String(Val);
                //if (SameText(TypeName, tInfo.TypeName) && tInfo.Decl != "")
                if (tInfo.Decl != "")
                {
                    p = tInfo.Decl.c_str();
                    e = p;
                    for (n = 0; n <= _val; n++)
                    {
                        b = e + 1;
                        e = strchr(b, ',');
                        if (!e) return "";
                    }
                    return tInfo.Decl.SubString(b - p + 1, e - b);
                }
            }
        }
    }
    return "";
}
//---------------------------------------------------------------------------
String __fastcall GetSetString(String TypeName, BYTE* ValAdr)
{
    int         n, m, idx, size;
    BYTE        b, *pVal;
    char        *pDecl, *p;
    WORD        *uses;
    MTypeInfo   tInfo;
    String      name, result = "";

    //Get from KB
    uses = KnowledgeBase.GetTypeUses(TypeName.c_str());
    idx = KnowledgeBase.GetTypeIdxByModuleIds(uses, TypeName.c_str());
    if (uses) delete[] uses;

    if (idx != -1)
    {
        idx = KnowledgeBase.TypeOffsets[idx].NamId;
        if (KnowledgeBase.GetTypeInfo(idx, INFO_DUMP, &tInfo))
        {
            if (tInfo.Decl.Pos("set of "))
            {
                size = tInfo.Size;
                name = TrimTypeName(tInfo.Decl.SubString(8, TypeName.Length()));
                uses = KnowledgeBase.GetTypeUses(name.c_str());
                idx = KnowledgeBase.GetTypeIdxByModuleIds(uses, name.c_str());
                if (uses) delete[] uses;

                if (idx != -1)
                {
                    idx = KnowledgeBase.TypeOffsets[idx].NamId;
                    if (KnowledgeBase.GetTypeInfo(idx, INFO_DUMP, &tInfo))
                    {
                        pVal = ValAdr;
                        pDecl = tInfo.Decl.c_str();
                        p = strtok(pDecl, ",()");
                        for (n = 0; n < size; n++)
                        {
                            b = *pVal;
                            for (m = 0; m < 8; m++)
                            {
                                if (b & ((DWORD)1 << m))
                                {
                                    if (result != "") result += ",";
                                    if (p)
                                        result += String(p);
                                    else
                                        result += "$" + Val2Str2(n * 8 + m);
                                }
                                if (p) p = strtok(0, ",)");
                            }
                            pVal++;
                        }
                    }
                }
            }
        }
    }
    if (result != "") result = "[" + result + "]";
    return result;
}
//---------------------------------------------------------------------------
void __fastcall AddFieldXref(PFIELDINFO fInfo, DWORD ProcAdr, int ProcOfs, char type)
{
    PXrefRec    recX;

    if (!fInfo->xrefs) fInfo->xrefs = new TList;

    if (!fInfo->xrefs->Count)
    {
        recX = new XrefRec;
        recX->type = type;
        recX->adr = ProcAdr;
        recX->offset = ProcOfs;
        fInfo->xrefs->Add((void*)recX);
        return;
    }

    int F = 0;
    recX = (PXrefRec)fInfo->xrefs->Items[F];
    if (ProcAdr + ProcOfs < recX->adr + recX->offset)
    {
        recX = new XrefRec;
        recX->type = type;
        recX->adr = ProcAdr;
        recX->offset = ProcOfs;
        fInfo->xrefs->Insert(F, (void*)recX);
        return;
    }
    int L = fInfo->xrefs->Count - 1;
    recX = (PXrefRec)fInfo->xrefs->Items[L];
    if (ProcAdr + ProcOfs > recX->adr + recX->offset)
    {
        recX = new XrefRec;
        recX->type = type;
        recX->adr = ProcAdr;
        recX->offset = ProcOfs;
        fInfo->xrefs->Add((void*)recX);
        return;
    }
    while (F < L)
    {
        int M = (F + L)/2;
        recX = (PXrefRec)fInfo->xrefs->Items[M];
        if (ProcAdr + ProcOfs <= recX->adr + recX->offset)
            L = M;
        else
            F = M + 1;
    }
    recX = (PXrefRec)fInfo->xrefs->Items[L];
    if (ProcAdr + ProcOfs != recX->adr + recX->offset)
    {
        recX = new XrefRec;
        recX->type = type;
        recX->adr = ProcAdr;
        recX->offset = ProcOfs;
        fInfo->xrefs->Insert(L, (void*)recX);
    }
}
//---------------------------------------------------------------------------
//---------------------------------------------------------------------------
void __fastcall AddPicode(int Pos, BYTE Op, String Name, int Ofs)
{
    if (Name == "") return;

	PInfoRec recN = GetInfoRec(Pos2Adr(Pos));
    //if (recN && recN->picode) return;
    
    if (!recN)
        recN = new InfoRec(Pos, ikUnknown);
    if (!recN->picode)
        recN->picode = new PICODE;
    recN->picode->Op = Op;
    recN->picode->Name = Name;
    if (Op == OP_CALL)
    	recN->picode->Ofs.Address = Ofs;
    else
    	recN->picode->Ofs.Offset = Ofs;
}
//---------------------------------------------------------------------------
int __fastcall SortUnitsByAdr(void *item1, void* item2)
{
    PUnitRec recU1 = (PUnitRec)item1;
    PUnitRec recU2 = (PUnitRec)item2;
    if (recU1->toAdr > recU2->toAdr) return 1;
    if (recU1->toAdr < recU2->toAdr) return -1;
    return 0;
}
//---------------------------------------------------------------------------
int __fastcall SortUnitsByOrd(void *item1, void* item2)
{
    PUnitRec recU1 = (PUnitRec)item1;
    PUnitRec recU2 = (PUnitRec)item2;
    if (recU1->iniOrder > recU2->iniOrder) return 1;
    if (recU1->iniOrder < recU2->iniOrder) return -1;
    return 0;
}
//---------------------------------------------------------------------------
int __fastcall SortUnitsByNam(void *item1, void* item2)
{
    PUnitRec recU1 = (PUnitRec)item1;
    PUnitRec recU2 = (PUnitRec)item2;
    String name1 = "";
    for (int n = 0; n < recU1->names->Count; n++)
    {
        if (n) name1 += "+";
        name1 += recU1->names->Strings[n];
    }
    String name2 = "";
    for (int n = 0; n < recU2->names->Count; n++)
    {
        if (n) name2 += "+";
        name2 += recU2->names->Strings[n];
    }
    int result = CompareText(name1, name2);
    if (result) return result;
    if (recU1->toAdr > recU2->toAdr) return 1;
    if (recU1->toAdr < recU2->toAdr) return -1;
    return 0;
}
//---------------------------------------------------------------------------
String __fastcall GetArrayElementType(String arrType)
{
    DWORD adr = GetOwnTypeAdr(arrType);
    if (IsValidImageAdr(adr) && idr.IsFlagSet(cfRTTI, Adr2Pos(adr)))
        return GetDynArrayTypeName(adr);

    int pos = arrType.Pos(" of ");
    if (!pos) return "";
    return Trim(arrType.SubString(pos + 4, arrType.Length()));
}
//---------------------------------------------------------------------------
int __fastcall GetArrayElementTypeSize(String arrType)
{
    String      _elType;

    _elType = GetArrayElementType(arrType);
    if (_elType == "") return 0;

    if (SameText(_elType, "procedure")) return 8;
    return GetTypeSize(_elType);
}
//---------------------------------------------------------------------------
void __fastcall Copy2Clipboard(TStrings* items, int leftMargin, bool asmCode)
{
    int     n, bufLen = 0;
    String  line;

    BusyCursor  cursor; //Show busy cursor inside this routine, restore on exit

    for (n = 0; n < items->Count; n++)
    {
        line = items->Strings[n];
        bufLen += line.Length() + 2;
    }
    //Last char must be 0
    bufLen++;

    if (bufLen)
    {
        char* buf = new char[bufLen];
        if (buf)
        {
            Clipboard()->Open();
            //Output data into buffer
            char *p = buf;
            for (n = 0; n < items->Count; n++)
            {
                line = items->Strings[n];
                p += sprintf(p, "%s", line.c_str() + leftMargin);
                if (asmCode && n) p--;
                *p = '\r'; p++;
                *p = '\n'; p++;
            }

            *p = 0;
            Clipboard()->SetTextBuf(buf);
            Clipboard()->Close();

            delete[] buf;
        }
    }
}
//---------------------------------------------------------------------------
String __fastcall GetModuleVersion(const String& module)
{
    DWORD dwDummy;
    DWORD dwFVISize = GetFileVersionInfoSize(module.c_str(), &dwDummy);
    if (!dwFVISize) return "";

    String strVersion = ""; //empty means not found, etc - some error

    LPBYTE lpVersionInfo = new BYTE[dwFVISize];
    if (GetFileVersionInfo(module.c_str(), 0, dwFVISize, lpVersionInfo))
    {
        UINT uLen;
        VS_FIXEDFILEINFO *lpFfi;
        if (VerQueryValue(lpVersionInfo, "\\", (LPVOID *)&lpFfi, &uLen))
        {
            DWORD dwFileVersionMS = lpFfi->dwFileVersionMS;
            DWORD dwFileVersionLS = lpFfi->dwFileVersionLS;
            DWORD dwLeftMost      = HIWORD(dwFileVersionMS);
            DWORD dwSecondLeft    = LOWORD(dwFileVersionMS);
            DWORD dwSecondRight   = HIWORD(dwFileVersionLS);
            DWORD dwRightMost     = LOWORD(dwFileVersionLS);

            strVersion.sprintf("%d.%d.%d.%d", dwLeftMost, dwSecondLeft, dwSecondRight, dwRightMost);
        }
    }
    delete[] lpVersionInfo;
    return strVersion;
}
//---------------------------------------------------------------------------
bool __fastcall IsBplByExport(const char* bpl)
{
	PIMAGE_NT_HEADERS			pHeader			= 0;
	PIMAGE_EXPORT_DIRECTORY		pExport			= 0;
	DWORD						*pFuncNames		= 0;
	WORD						*pFuncOrdinals	= 0;
	DWORD						*pFuncAddr		= 0;
	DWORD						pName			= 0;
	DWORD						imageBase		= 0;
	char*						szDll			= 0;
	bool						result			= 0;
    bool    haveInitializeFunc = false;
    bool    haveFinalizeFunc = false;
    bool    haveGetPackageInfoTableFunc = false;

	HMODULE hLib = LoadLibraryEx(bpl, 0, LOAD_LIBRARY_AS_DATAFILE);
	imageBase = (DWORD)(DWORD_PTR)hLib;

	if (hLib)
    {
		pHeader = ImageNtHeader(hLib);

		if (pHeader && pHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress &&
			pHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size)
		{
			pExport = (PIMAGE_EXPORT_DIRECTORY)(DWORD_PTR)
					(pHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + imageBase);

			szDll = (char*)(imageBase + pExport->Name);

			pFuncOrdinals	=(WORD*) (imageBase + pExport->AddressOfNameOrdinals);
			pFuncNames		=(DWORD*)(imageBase + pExport->AddressOfNames);
			pFuncAddr		=(DWORD*)(imageBase + pExport->AddressOfFunctions);

			for (int i = 0; i < pExport->NumberOfFunctions; i++)
			{
				int index = -1;
				for (int j = 0; j < pExport->NumberOfNames; j++)
				{
					if (pFuncOrdinals[j] == i)
                    {
						index = j;
						break;
					}
				}
				if (index != -1)
				{
                    pName = pFuncNames[index];
                    String curFunc = String((char*)imageBase + pName);
                    //Every BPL has a function called @GetPackageInfoTable, Initialize and Finalize.
                    //lets catch it!
                    if (!haveInitializeFunc) haveInitializeFunc = (curFunc == "Initialize");
                    if (!haveFinalizeFunc) haveFinalizeFunc = (curFunc == "Finalize");
                    if (!haveGetPackageInfoTableFunc) haveGetPackageInfoTableFunc = (curFunc == "@GetPackageInfoTable");
				}
                if (haveInitializeFunc && haveFinalizeFunc && haveGetPackageInfoTableFunc) break;
			}

			result = haveInitializeFunc && haveFinalizeFunc;
		}
		FreeLibrary(hLib);
	}
	return result;
}
//---------------------------------------------------------------------------
//toAdr:dec reg
int __fastcall Idr64Manager::IsInitStackViaLoop(DWORD fromAdr, DWORD toAdr)
{
    int         _mnemIdx, stackSize = 0;
    DWORD       curAdr;
    int         instrLen;
    DISINFO     _disInfo;

    curAdr = fromAdr;
    while (curAdr <= toAdr)
    {
        instrLen = GetDisasm().Disassemble(Code + Adr2Pos(curAdr), curAdr, &_disInfo, 0);
        //if (!instrLen) return 0;
        if (!instrLen)
        {
            curAdr++;
            continue;
        }
        _mnemIdx = _disInfo.MnemIdx;
        //push ...
        if (_mnemIdx == IDX_PUSH)
        {
            stackSize += 8;
            curAdr += instrLen;
            continue;
        }
        //add rsp, ...
        if (_mnemIdx == IDX_ADD && _disInfo.OpType[0] == otREG && _disInfo.OpRegIdx[0] == REG_RSP && _disInfo.OpType[1] == otIMM)
        {
            if ((int)_disInfo.Immediate < 0) stackSize -= (int)_disInfo.Immediate;
            curAdr += instrLen;
            continue;
        }
        //sub rsp, ...
        if (_mnemIdx == IDX_SUB && _disInfo.OpType[0] == otREG && _disInfo.OpRegIdx[0] == REG_RSP && _disInfo.OpType[1] == otIMM)
        {
            if ((int)_disInfo.Immediate > 0) stackSize += (int)_disInfo.Immediate;
            curAdr += instrLen;
            continue;
        }
        //dec
        if (_mnemIdx == IDX_DEC)
        {
            curAdr += instrLen;
            if (curAdr == toAdr) return stackSize;
        }
        break;
    }
    return 0;
}

//---------------------------------------------------------------------------
static int IdxToIdx32Tab[24] = {
16, 17, 18, 19, 16, 17, 18, 19, 16, 17, 18, 19, 20, 21, 22, 23, 16, 17, 18, 19, 20, 21, 22, 23
};
int __fastcall GetReg32Idx(int Idx)
{
    return IdxToIdx32Tab[Idx];
}
//---------------------------------------------------------------------------
bool __fastcall IsSameRegister(int Idx1, int Idx2)
{
    return (GetReg32Idx(Idx1) == GetReg32Idx(Idx2));
}
//---------------------------------------------------------------------------
bool __fastcall IsAnalyzedAdr(DWORD Adr)
{
    bool    analyze = false;
    for (int n = 0; n < SegmentList->Count; n++)
    {
        PSegmentInfo segInfo = (PSegmentInfo)SegmentList->Items[n];
        if (segInfo->Start <= Adr && Adr < segInfo->Start + segInfo->Size)
        {
            if (!(segInfo->Flags & 0x80000)) analyze = true;
            break;
        }
    }
    return analyze;
}
//---------------------------------------------------------------------------
//Check that fromAdr is BoundErr sequence
int __fastcall Idr64Manager::IsBoundErr(DWORD fromAdr)
{
    int         _pos, _instrLen;
    DWORD       _adr;
    PInfoRec    _recN;
    DISINFO     _disInfo;

    _pos = Adr2Pos(fromAdr); _adr = fromAdr;
    while (idr.IsFlagSet(cfSkip, _pos))
    {
        _instrLen = GetDisasm().Disassemble(Code + _pos, (__int64)_adr, &_disInfo, 0);
        _adr += _instrLen;
        if (_disInfo.Call && IsValidImageAdr(_disInfo.Immediate))
        {
            _recN = GetInfoRec(_disInfo.Immediate);
            if (_recN->SameName("@BoundErr")) return _adr - fromAdr;
        }
        _pos += _instrLen;
    }
    return 0;
}
//---------------------------------------------------------------------------
bool __fastcall IsConnected(DWORD fromAdr, DWORD toAdr)
{
    int         n, _pos, _instrLen;
    DWORD       _adr;
    DISINFO     _disInfo;

    _pos = Adr2Pos(fromAdr); _adr = fromAdr;
    for (n = 0; n < 32; n++)
    {
        _instrLen = GetDisasm().Disassemble(Code + _pos, (__int64)_adr, &_disInfo, 0);
        if (_disInfo.Conditional && _disInfo.Immediate == toAdr) return true;
        _pos += _instrLen; _adr += _instrLen;
    }
    return false;
}
//---------------------------------------------------------------------------
//Check that fromAdr points to Exit
bool __fastcall Idr64Manager::IsExit(DWORD fromAdr)
{
    BYTE        _op;
    int         _pos, _instrLen;
    DWORD       _adr;
    DISINFO     _disInfo;

    if (!IsValidCodeAdr(fromAdr)) return 0;
    _pos = Adr2Pos(fromAdr); _adr = fromAdr;
    
    while (1)
    {
        _pos += 8; _adr += 8;
        _instrLen = GetDisasm().Disassemble(Code + _pos, (__int64)_adr, &_disInfo, 0);
        _op = GetDisasm().GetOp(_disInfo.MnemIdx);
        if (_op == OP_PUSH || _op == OP_JMP)
        {
            _adr = _disInfo.Immediate;
            _pos = Adr2Pos(_adr);
        }
        else
        {
            return false;
        }
    }
    while (1)
    {
        _instrLen = GetDisasm().Disassemble(Code + _pos, (__int64)_adr, &_disInfo, 0);
        if (_disInfo.Ret) return true;
        _op = GetDisasm().GetOp(_disInfo.MnemIdx);
        if (_op == OP_POP)
        {
            _pos += _instrLen;
            _adr += _instrLen;
            continue;
        }
        if (_op == OP_MOV && _disInfo.OpType[0] == otREG &&
           (IsSameRegister(_disInfo.OpRegIdx[0], 16) || IsSameRegister(_disInfo.OpRegIdx[0], 20)))
        {
            _pos += _instrLen;
            _adr += _instrLen;
            continue;
        }
        break;
    }
    return false;
}
//---------------------------------------------------------------------------
DWORD __fastcall Idr64Manager::IsGeneralCase(DWORD fromAdr, int retAdr)
{
    int         _regIdx = -1, _pos, _mnemIdx;
    DWORD       _curAdr = fromAdr, _jmpAdr = 0;
    int         _curPos = Adr2Pos(fromAdr);
    int         _len, _num1 = 0;
    DISINFO     _disInfo;

    if (!IsValidCodeAdr(fromAdr)) return 0;

    while (1)
    {
        _len = GetDisasm().Disassemble(Code + _curPos, (__int64)_curAdr, &_disInfo, 0);
        _mnemIdx = _disInfo.MnemIdx;
        //Switch at current address
        if (IsFlagSet(cfSwitch, _curPos))
        {
            GetDisasm().Disassemble(Code + _curPos + _len, (__int64)(_curAdr + _len), &_disInfo, 0);
            _mnemIdx = _disInfo.MnemIdx;
            if (_mnemIdx == IDX_JA)
            {
                if (IsValidCodeAdr(_disInfo.Immediate))
                    return _disInfo.Immediate;
                else
                    return 0;
            }
        }
        //Switch at next address
        if (IsFlagSet(cfSwitch, _curPos + _len))
        {
            _len += GetDisasm().Disassemble(Code + _curPos + _len, (__int64)(_curAdr + _len), &_disInfo, 0);
            GetDisasm().Disassemble(Code + _curPos + _len, (__int64)(_curAdr + _len), &_disInfo, 0);
            _mnemIdx = _disInfo.MnemIdx;
            if (_mnemIdx == IDX_JA)
            {
                if (IsValidCodeAdr(_disInfo.Immediate))
                    return _disInfo.Immediate;
                else
                    return 0;
            }
        }
        //cmp reg, imm
        if (_mnemIdx == IDX_CMP && _disInfo.OpType[0] == otREG && _disInfo.OpType[1] == otIMM)
        {
            _regIdx = _disInfo.OpRegIdx[0];
            _len += GetDisasm().Disassemble(Code + _curPos + _len, (__int64)(_curAdr + _len), &_disInfo, 0);
            _mnemIdx = _disInfo.MnemIdx;
            if (_mnemIdx == IDX_JB || _mnemIdx == IDX_JG || _mnemIdx == IDX_JGE)
            {
                if (IsGeneralCase(_disInfo.Immediate, retAdr))
                {
                    _curAdr += _len;
                    _curPos += _len;

                    _len = GetDisasm().Disassemble(Code + _curPos, (__int64)(_curAdr), &_disInfo, 0);
                    _mnemIdx = _disInfo.MnemIdx;
                    if (_mnemIdx == IDX_JE)
                    {
                        _curAdr += _len;
                        _curPos += _len;
                        //continue;
                    }
                    continue;
                }
                break;
            }
        }
        //sub reg, imm; dec reg
        if ((_mnemIdx == IDX_SUB && _disInfo.OpType[0] == otREG && _disInfo.OpType[1] == otIMM) ||
            (_mnemIdx == IDX_DEC && _disInfo.OpType[0] == otREG))
        {
            _num1++;
            if (_regIdx == -1)
                _regIdx = _disInfo.OpRegIdx[0];
            else if (!IsSameRegister(_regIdx, _disInfo.OpRegIdx[0]))
                break;

            _len += GetDisasm().Disassemble(Code + _curPos + _len, (__int64)(_curAdr + _len), &_disInfo, 0);
            _mnemIdx = _disInfo.MnemIdx;
            if (_mnemIdx == IDX_SUB && IsSameRegister(_regIdx, _disInfo.OpRegIdx[0]))
            {
                _len += GetDisasm().Disassemble(Code + _curPos + _len, (__int64)(_curAdr + _len), &_disInfo, 0);
                _mnemIdx = _disInfo.MnemIdx;
            }
            if (_mnemIdx == IDX_JB)
            {
                _curAdr += _len;
                _curPos += _len;
                _len = GetDisasm().Disassemble(Code + _curPos, (__int64)_curAdr, &_disInfo, 0);
                _mnemIdx = _disInfo.MnemIdx;
                if (_mnemIdx == IDX_JE)
                {
                    _curAdr += _len;
                    _curPos += _len;
                }
                continue;
            }
            if (_mnemIdx == IDX_JE)
            {
                _pos = idr.GetNearestUpInstruction(Adr2Pos(_disInfo.Immediate));
                GetDisasm().Disassemble(Code + _pos, (__int64)Pos2Adr(_pos), &_disInfo, 0);
                _mnemIdx = _disInfo.MnemIdx;
                if (_mnemIdx == IDX_JMP)
                    _jmpAdr = _disInfo.Immediate;
                if (_disInfo.Ret)
                    _jmpAdr = Pos2Adr(GetLastLocPos(retAdr));
                _curAdr += _len;
                _curPos += _len;
                continue;
            }
            if (_mnemIdx == IDX_JNE)
            {
                if (!_jmpAdr)
                {
                    //if only one dec or sub then it is simple if...else construction
                    if (_num1 == 1) return 0;
                    return _disInfo.Immediate;
                }
                if (_disInfo.Immediate == _jmpAdr) return _jmpAdr;
            }
            break;
        }
        //add reg, imm; inc reg
        if ((_mnemIdx == IDX_ADD && _disInfo.OpType[0] == otREG && _disInfo.OpType[1] == otIMM) ||
            (_mnemIdx == IDX_INC && _disInfo.OpType[0] == otREG))
        {
            _num1++;
            if (_regIdx == -1)
                _regIdx = _disInfo.OpRegIdx[0];
            else if (!IsSameRegister(_regIdx, _disInfo.OpRegIdx[0]))
                break;

            _len += GetDisasm().Disassemble(Code + _curPos + _len, (__int64)(_curAdr + _len), &_disInfo, 0);
            _mnemIdx = _disInfo.MnemIdx;
            if (_mnemIdx == IDX_SUB)
            {
               _len += GetDisasm().Disassemble(Code + _curPos + _len, (__int64)(_curAdr + _len), &_disInfo, 0);
               _mnemIdx = _disInfo.MnemIdx;
               if (_mnemIdx == IDX_JB)
               {
                    _curAdr += _len;
                    _curPos += _len;
                    continue;
               }
            }
            if (_mnemIdx == IDX_JE)
            {
                _curAdr += _len;
                _curPos += _len;
                continue;
            }
            break;
        }
        if (_mnemIdx == IDX_JMP)
        {
            if (IsValidCodeAdr(_disInfo.Immediate))
                return _disInfo.Immediate;
            else
                return 0;
        }
        break;
    }
    return 0;
}
//---------------------------------------------------------------------------
//check
//xor reg, reg
//mov reg,...
bool __fastcall Idr64Manager::IsXorMayBeSkipped(DWORD fromAdr)
{
    DWORD       _curAdr = fromAdr;
    int         _instrlen, _regIdx, _mnemIdx;
    int         _curPos = Adr2Pos(fromAdr);
    DISINFO     _disInfo;

    _instrlen = GetDisasm().Disassemble(Code + _curPos, (__int64)_curAdr, &_disInfo, 0);
    _mnemIdx = _disInfo.MnemIdx;
    if (_mnemIdx == IDX_XOR && _disInfo.OpType[0] == otREG && _disInfo.OpType[1] == otREG && _disInfo.OpRegIdx[0] == _disInfo.OpRegIdx[1])
    {
        _regIdx = _disInfo.OpRegIdx[0];
        _curPos += _instrlen; _curAdr += _instrlen;
        GetDisasm().Disassemble(Code + _curPos, (__int64)_curAdr, &_disInfo, 0);
        _mnemIdx = _disInfo.MnemIdx;
        if (_mnemIdx == IDX_MOV && _disInfo.OpType[0] == otREG && IsSameRegister(_disInfo.OpRegIdx[0], _regIdx)) return true;
    }
    return false;
}
//---------------------------------------------------------------------------
String __fastcall UnmangleName(String Name)
{
    int     pos;
    //skip first '@'
    String  Result = Name.SubString(2, Name.Length());
    String  LeftPart = Result;
    String  RightPart = "";

    int breakPos = Result.Pos("$");
    if (breakPos)
    {
        if (breakPos == 1)//
        LeftPart = Result.SubString(1, breakPos - 1);
        RightPart = Result.SubString(breakPos + 1, Result.Length());
    }
    if (*LeftPart.AnsiLastChar() == '@')
        LeftPart.SetLength(LeftPart.Length() - 1);
    while (1)
    {
        pos = LeftPart.Pos("@@");
        if (!pos) break;
        LeftPart[pos + 1] = '_';
    }
    int num = 0;
    while (1)
    {
        pos = LeftPart.Pos("@");
        if (!pos) break;
        LeftPart[pos] = '.';
        num++;
    }
    while (1)
    {
        pos = LeftPart.Pos("._");
        if (!pos) break;
        LeftPart[pos + 1] = '@';
    }
}
//---------------------------------------------------------------------------
//Check construction (after cdq)
//xor rax, rdx
//sub rax, rdx
//return bytes to skip, if Abs, else return 0
int __fastcall Idr64Manager::IsAbs(DWORD fromAdr)
{
    int         _curPos = Adr2Pos(fromAdr), _instrLen, _mnemIdx;
    DWORD       _dd, _curAdr = fromAdr;
    DISINFO     _disInfo;

    _instrLen = GetDisasm().Disassemble(Code + _curPos, (__int64)_curAdr, &_disInfo, 0);
    _mnemIdx = _disInfo.MnemIdx;
    if (_mnemIdx == IDX_XOR &&
        _disInfo.OpType[0] == otREG &&
        _disInfo.OpType[1] == otREG &&
        _disInfo.OpRegIdx[0] == REG_RAX &&
        _disInfo.OpRegIdx[1] == REG_RDX)
    {
        _curPos += _instrLen; _curAdr += _instrLen;
        _instrLen = GetDisasm().Disassemble(Code + _curPos, (__int64)_curAdr, &_disInfo, 0);
        _mnemIdx = _disInfo.MnemIdx;
        if (_mnemIdx == IDX_SUB &&
            _disInfo.OpType[0] == otREG &&
            _disInfo.OpType[1] == otREG &&
            _disInfo.OpRegIdx[0] == REG_RAX &&
            _disInfo.OpRegIdx[1] == REG_RDX)
        {
            return (_curAdr + _instrLen) - fromAdr;
        }
    }
    return 0;
}
//---------------------------------------------------------------------------
//Check construction
//jxx @1
//call @IntOver
//@1:
//return bytes to skip, if @IntOver, else return 0
int __fastcall Idr64Manager::IsIntOver(DWORD fromAdr)
{
    int         _instrLen, _curPos = Adr2Pos(fromAdr);
    DWORD       _curAdr = fromAdr;
    PInfoRec    _recN;
    DISINFO     _disInfo;

    _instrLen = GetDisasm().Disassemble(Code + _curPos, (__int64)_curAdr, &_disInfo, 0);
    if (_disInfo.Branch && _disInfo.Conditional)
    {
        _curPos += _instrLen; _curAdr += _instrLen;
        _instrLen = GetDisasm().Disassemble(Code + _curPos, (__int64)_curAdr, &_disInfo, 0);
        if (_disInfo.Call)
        {
            if (IsValidCodeAdr(_disInfo.Immediate))
            {
                _recN = GetInfoRec(_disInfo.Immediate);
                if (_recN && _recN->SameName("@IntOver")) return (_curAdr + _instrLen) - fromAdr;
            }
        }
    }
    return 0;
}
//---------------------------------------------------------------------------
//Check construction (test reg, reg)
//test reg, reg
//jz @1
//mov reg, [reg-8]
//or-------------------------------------------------------------------------
//test reg, reg
//jz @1
//sub reg, 8
//mov reg, [reg]
int __fastcall Idr64Manager::IsInlineLengthTest(DWORD fromAdr)
{
    int         _curPos = Adr2Pos(fromAdr), _instrLen, _regIdx = -1, _mnemIdx;
    DWORD       _adr = 0, _curAdr = fromAdr;
    DISINFO     _disInfo;

    _instrLen = GetDisasm().Disassemble(Code + _curPos, (__int64)_curAdr, &_disInfo, 0);
    _mnemIdx = _disInfo.MnemIdx;
    if (_mnemIdx == IDX_TEST &&
        _disInfo.OpType[0] == otREG &&
        _disInfo.OpType[1] == otREG &&
        _disInfo.OpRegIdx[0] == _disInfo.OpRegIdx[1])
    {
        _regIdx = _disInfo.OpRegIdx[0];
        _curPos += _instrLen; _curAdr += _instrLen;
        _instrLen = GetDisasm().Disassemble(Code + _curPos, (__int64)_curAdr, &_disInfo, 0);
        _mnemIdx = _disInfo.MnemIdx;
        if (_mnemIdx == IDX_JE)
        {
            _adr = _disInfo.Immediate;
            _curPos += _instrLen; _curAdr += _instrLen;
            _instrLen = GetDisasm().Disassemble(Code + _curPos, (__int64)_curAdr, &_disInfo, 0);
            _mnemIdx = _disInfo.MnemIdx;
            //mov reg, [reg-8]
            if (_mnemIdx == 'vom' &&
                _disInfo.OpType[0] == otREG &&
                _disInfo.OpType[1] == otMEM &&
                _disInfo.BaseReg == _regIdx &&
                _disInfo.IndxReg == -1 &&
                _disInfo.Offset == -8)
            {
                if (_adr == _curAdr + _instrLen) return (_curAdr + _instrLen) - fromAdr;
            }
            //sub reg, 8
            if (_mnemIdx == IDX_SUB &&
                _disInfo.OpType[0] == otREG &&
                _disInfo.OpType[1] == otIMM &&
                _disInfo.Immediate == 8)
            {
                _curPos += _instrLen; _curAdr += _instrLen;
                _instrLen = GetDisasm().Disassemble(Code + _curPos, (__int64)_curAdr, &_disInfo, 0);
                _mnemIdx = _disInfo.MnemIdx;
                //mov reg, [reg]
                if (_mnemIdx == IDX_MOV &&
                    _disInfo.OpType[0] == otREG &&
                    _disInfo.OpType[1] == otMEM &&
                    _disInfo.BaseReg == _regIdx &&
                    _disInfo.IndxReg == -1 &&
                    _disInfo.Offset == 0)
                {
                    if (_adr == _curAdr + _instrLen) return (_curAdr + _instrLen) - fromAdr;
                }
            }
        }
    }
    return 0;
}
//---------------------------------------------------------------------------
//cmp [lvar], 0
//jz @1
//mov reg, [lvar]
//sub reg, 8
//mov reg, [reg]
//mov [lvar], reg
int __fastcall Idr64Manager::IsInlineLengthCmp(DWORD fromAdr)
{
    BYTE        _op;
    int         _curPos = Adr2Pos(fromAdr), _instrLen, _regIdx = -1;
    int         _baseReg, _offset, _mnemIdx;
    DWORD       _adr = 0, _curAdr = fromAdr;
    DISINFO     _disInfo;

    _instrLen = GetDisasm().Disassemble(Code + _curPos, (__int64)_curAdr, &_disInfo, 0);
    _op = GetDisasm().GetOp(_disInfo.MnemIdx);
    if (_op == OP_CMP &&
        _disInfo.OpType[0] == otMEM &&
        _disInfo.OpType[1] == otIMM &&
        _disInfo.Immediate == 0)
    {
        _baseReg = _disInfo.BaseReg;
        _offset = _disInfo.Offset;
        _curPos += _instrLen; _curAdr += _instrLen;
        _instrLen = GetDisasm().Disassemble(Code + _curPos, (__int64)_curAdr, &_disInfo, 0);
        _mnemIdx = _disInfo.MnemIdx;
        if (_mnemIdx == IDX_JE)
        {
            _adr = _disInfo.Immediate;
            _curPos += _instrLen; _curAdr += _instrLen;
            _instrLen = GetDisasm().Disassemble(Code + _curPos, (__int64)_curAdr, &_disInfo, 0);
            _op = GetDisasm().GetOp(_disInfo.MnemIdx);
            //mov reg, [lvar]
            if (_op == OP_MOV &&
                _disInfo.OpType[0] == otREG &&
                _disInfo.OpType[1] == otMEM &&
                _disInfo.BaseReg == _baseReg &&
                _disInfo.Offset == _offset)
            {
                _regIdx = _disInfo.OpRegIdx[0];
                _curPos += _instrLen; _curAdr += _instrLen;
                _instrLen = GetDisasm().Disassemble(Code + _curPos, (__int64)_curAdr, &_disInfo, 0);
                _op = GetDisasm().GetOp(_disInfo.MnemIdx);
                //sub reg, 8
                if (_op == OP_SUB &&
                    _disInfo.OpType[0] == otREG &&
                    _disInfo.OpType[1] == otIMM &&
                    _disInfo.Immediate == 8)
                {
                    _curPos += _instrLen; _curAdr += _instrLen;
                    _instrLen = GetDisasm().Disassemble(Code + _curPos, (__int64)_curAdr, &_disInfo, 0);
                    _op = GetDisasm().GetOp(_disInfo.MnemIdx);
                    //mov reg, [reg]
                    if (_op == OP_MOV &&
                        _disInfo.OpType[0] == otREG &&
                        _disInfo.OpType[1] == otMEM &&
                        _disInfo.BaseReg == _regIdx &&
                        _disInfo.IndxReg == -1 &&
                        _disInfo.Offset == 0)
                    {
                        _curPos += _instrLen; _curAdr += _instrLen;
                        _instrLen = GetDisasm().Disassemble(Code + _curPos, (__int64)_curAdr, &_disInfo, 0);
                        _op = GetDisasm().GetOp(_disInfo.MnemIdx);
                        //mov [lvar], reg
                        if (_op == OP_MOV &&
                            _disInfo.OpType[0] == otMEM &&
                            _disInfo.OpType[1] == otREG &&
                            _disInfo.BaseReg == _baseReg &&
                            _disInfo.Offset == _offset)
                        {
                            if (_adr == _curAdr + _instrLen) return (_curAdr + _instrLen) - fromAdr;
                        }
                    }
                }
            }
        }
    }
    return 0;
}
//---------------------------------------------------------------------------
//test reg, reg
//jns @1
//add reg, (2^k - 1)
//sar reg, k
//@1
int __fastcall Idr64Manager::IsInlineDiv(DWORD fromAdr, int* div)
{
    BYTE        _op;
    int         _curPos = Adr2Pos(fromAdr), _instrLen, _regIdx = -1, _mnemIdx;
    DWORD       _adr, _curAdr = fromAdr, _imm;
    DISINFO     _disInfo;

    _instrLen = GetDisasm().Disassemble(Code + _curPos, (__int64)_curAdr, &_disInfo, 0);
    _op = GetDisasm().GetOp(_disInfo.MnemIdx);
    if (_op == OP_TEST &&
        _disInfo.OpType[0] == otREG &&
        _disInfo.OpType[1] == otREG &&
        _disInfo.OpRegIdx[0] == _disInfo.OpRegIdx[1])
    {
        _regIdx = _disInfo.OpRegIdx[0];
        _curPos += _instrLen; _curAdr += _instrLen;
        _instrLen = GetDisasm().Disassemble(Code + _curPos, (__int64)_curAdr, &_disInfo, 0);
        _mnemIdx = _disInfo.MnemIdx;
        if (_mnemIdx == IDX_JNS)
        {
            _adr = _disInfo.Immediate;
            _curPos += _instrLen; _curAdr += _instrLen;
            _instrLen = GetDisasm().Disassemble(Code + _curPos, (__int64)_curAdr, &_disInfo, 0);
            _op = GetDisasm().GetOp(_disInfo.MnemIdx);
            if (_op == OP_ADD &&
                _disInfo.OpType[0] == otREG &&
                _disInfo.OpRegIdx[0] == _regIdx &&
                _disInfo.OpType[1] == otIMM)
            {
                _imm = _disInfo.Immediate + 1;
                _curPos += _instrLen; _curAdr += _instrLen;
                _instrLen = GetDisasm().Disassemble(Code + _curPos, (__int64)_curAdr, &_disInfo, 0);
                _op = GetDisasm().GetOp(_disInfo.MnemIdx);
                if (_op == OP_SAR &&
                    _disInfo.OpType[0] == otREG &&
                    _disInfo.OpRegIdx[0] == _regIdx &&
                    _disInfo.OpType[1] == otIMM)
                {
                    if (((DWORD)1 << _disInfo.Immediate) == _imm)
                    {
                        *div = _imm;
                        return (_curAdr + _instrLen) - fromAdr;
                    }
                }
            }
        }
    }
    return 0;
}
//---------------------------------------------------------------------------
//and reg, imm
//jns @1
//dec reg
//or reg, imm
//inc reg
//@1
int __fastcall Idr64Manager::IsInlineMod(DWORD fromAdr, int* mod)
{
    BYTE        _op;
    int         _curPos = Adr2Pos(fromAdr), _instrLen, _regIdx = -1, _mnemIdx;
    DWORD       _adr = 0, _curAdr = fromAdr, _imm;
    DISINFO     _disInfo;

    _instrLen = GetDisasm().Disassemble(Code + _curPos, (__int64)_curAdr, &_disInfo, 0);
    _op = GetDisasm().GetOp(_disInfo.MnemIdx);
    if (_op == OP_AND &&
        _disInfo.OpType[0] == otREG &&
        _disInfo.OpType[1] == otIMM &&
        (_disInfo.Immediate & 0x80000000) != 0)
    {
        _regIdx = _disInfo.OpRegIdx[0];
        _imm = _disInfo.Immediate & 0x7FFFFFFF;
        _curPos += _instrLen; _curAdr += _instrLen;
        _instrLen = GetDisasm().Disassemble(Code + _curPos, (__int64)_curAdr, &_disInfo, 0);
        _mnemIdx = _disInfo.MnemIdx;
        if (_mnemIdx == IDX_JNS)
        {
            _adr = _disInfo.Immediate;
            _curPos += _instrLen; _curAdr += _instrLen;
            _instrLen = GetDisasm().Disassemble(Code + _curPos, (__int64)_curAdr, &_disInfo, 0);
            _op = GetDisasm().GetOp(_disInfo.MnemIdx);
            if (_op == OP_DEC &&
                _disInfo.OpType[0] == otREG &&
                _disInfo.OpRegIdx[0] == _regIdx)
            {
                _curPos += _instrLen; _curAdr += _instrLen;
                _instrLen = GetDisasm().Disassemble(Code + _curPos, (__int64)_curAdr, &_disInfo, 0);
                _op = GetDisasm().GetOp(_disInfo.MnemIdx);
                if (_op == OP_OR &&
                    _disInfo.OpType[0] == otREG &&
                    _disInfo.OpType[1] == otIMM &&
                    _disInfo.OpRegIdx[0] == _regIdx &&
                    _disInfo.Immediate + _imm == 0xFFFFFFFF)
                {
                    _curPos += _instrLen; _curAdr += _instrLen;
                    _instrLen = GetDisasm().Disassemble(Code + _curPos, (__int64)_curAdr, &_disInfo, 0);
                    _op = GetDisasm().GetOp(_disInfo.MnemIdx);
                    if (_op == OP_INC &&
                        _disInfo.OpType[0] == otREG &&
                        _disInfo.OpRegIdx[0] == _regIdx)
                    {
                        if (_adr == _curAdr + _instrLen)
                        {
                            *mod = _imm + 1;
                            return (_curAdr + _instrLen) - fromAdr;
                        }
                    }
                }
            }
        }
    }
    return 0;
}
//---------------------------------------------------------------------------
int __fastcall GetLastLocPos(int fromAdr)
{
    int     _pos = Adr2Pos(fromAdr);
    while (1)
    {
        if (idr.IsFlagSet(cfLoc, _pos)) return _pos;
        _pos--;
    }
}
//---------------------------------------------------------------------------
bool __fastcall IsDefaultName(String AName)
{
    for (int Idx = 0; Idx < 8; Idx++)
    {
        if (SameText(AName, String(GetDisasm().GetrgszReg32(Idx)))) return true;
    }
    if (SameText(AName.SubString(1, 5), "lvar_")) return true;
    if (SameText(AName.SubString(1, 5), "gvar_")) return true;
    return false; 
}
//---------------------------------------------------------------------------
int __fastcall FloatNameToFloatType(String AName)
{
    if (SameText(AName, "Single")) return FT_SINGLE;
    if (SameText(AName, "Double")) return FT_DOUBLE;
    if (SameText(AName, "Extended")) return FT_EXTENDED;
    if (SameText(AName, "Real")) return FT_REAL;
    if (SameText(AName, "Comp")) return FT_COMP;
    if (SameText(AName, "Currency")) return FT_CURRENCY;
    return -1;
}
//---------------------------------------------------------------------------
bool __fastcall MatchCode(BYTE* code, MProcInfo* pInfo)
{
	if (!code || !pInfo) return false;

    DWORD _dumpSz = pInfo->DumpSz;
    //ret
    if (_dumpSz < 2) return false;

    BYTE *_dump = pInfo->Dump;
    BYTE *_relocs = _dump + _dumpSz;
    //jmp XXXXXXXX
    if (_dumpSz == 5 && _dump[0] == 0xE9 && _relocs[1] == 0xFF) return false;
    //call XXXXXXXX ret
    if (_dumpSz == 6 && _dump[0] == 0xE8 && _relocs[1] == 0xFF && _dump[5] == 0xC3) return false;

    for (int n = 0; n < _dumpSz;)
    {
        //Relos skip
        if (_relocs[n] == 0xFF)
        {
            n += 4;
            continue;
        }
        if (code[n] != _dump[n])
            return false;

        n++;
    }

    return true;
}
//---------------------------------------------------------------------------
static TColor SavedPenColor;
static TColor SavedBrushColor;
static TColor SavedFontColor;
static TBrushStyle SavedBrushStyle;
//---------------------------------------------------------------------------
void __fastcall SaveCanvas(TCanvas* ACanvas)
{
    SavedPenColor = ACanvas->Pen->Color;
    SavedBrushColor = ACanvas->Brush->Color;
    SavedFontColor = ACanvas->Font->Color;
    SavedBrushStyle = ACanvas->Brush->Style;
}
//---------------------------------------------------------------------------
void __fastcall RestoreCanvas(TCanvas* ACanvas)
{
    ACanvas->Pen->Color = SavedPenColor;
    ACanvas->Brush->Color = SavedBrushColor;
    ACanvas->Font->Color = SavedFontColor;
    ACanvas->Brush->Style = SavedBrushStyle;
}
//---------------------------------------------------------------------------
void __fastcall DrawOneItem(String AItem, TCanvas* ACanvas, TRect &ARect, TColor AColor, int flags)
{
    SaveCanvas(ACanvas);
    ARect.Left = ARect.Right;
    ARect.Right += ACanvas->TextWidth(AItem);
    TRect R1 = Rect(ARect.Left -1, ARect.Top, ARect.Right, ARect.Bottom - 1);
    if ((GetDisasm().IsReg(SelectedAsmItem.c_str()) >= 0 && GetDisasm().IsSimilarRegs(AItem.c_str(), SelectedAsmItem.c_str())) ||
        SameText(AItem, SelectedAsmItem))
    {
        ACanvas->Brush->Color = TColor(0x80DDFF);
        ACanvas->Brush->Style = bsSolid;
        ACanvas->FillRect(R1);
        ACanvas->Brush->Style = bsClear;
        ACanvas->Pen->Color = TColor(0x226DA8);;
        ACanvas->Rectangle(R1);
    }
    ACanvas->Font->Color = AColor;
    ACanvas->TextOut(ARect.Left, ARect.Top, AItem);
    RestoreCanvas(ACanvas);
}
//---------------------------------------------------------------------------
//Check construction equality ((Int64)val = XXX)
//cmp XXX,XXX -> set cfSkip (_skipAdr1 = address of this instruction)
//jne @1 -> set cfSkip (_skipAdr2 = address of this instruction)
//cmp XXX,XXX
//jne @1
//...
//@1:
int __fastcall Idr64Manager::ProcessInt64Equality(DWORD fromAdr, DWORD* maxAdr)
{
    BYTE        _op, _b;
    int         _instrLen, n, _curPos;
    DWORD       _curAdr, _adr1, _maxAdr;
    DWORD       _skipAdr1, _skipAdr2;
    DISINFO     _disInfo;

    _curAdr = fromAdr; _curPos = Adr2Pos(_curAdr); _maxAdr = 0;
    for (n = 1; n <= 1024; n++)
    {
        _instrLen = GetDisasm().Disassemble(Code + Adr2Pos(_curAdr), _curAdr, &_disInfo, 0);

        _b = *(Code + _curPos);
        if (_b == 0xF) _b = *(Code + _curPos + 1);
        _b = (_b & 0xF) + 'A';

        _op = GetDisasm().GetOp(_disInfo.MnemIdx);
        if (n == 1)//cmp XXX,XXX
        {
            if (!(_op == OP_CMP)) break;
            _skipAdr1 = _curAdr;
        }
        else if (n == 2)//jne @1
        {
            if (!(_disInfo.Branch && _disInfo.Conditional && _b == 'F')) break;
            _skipAdr2 = _curAdr;
            _adr1 = _disInfo.Immediate;//@1
            if (_adr1 > _maxAdr) _maxAdr = _adr1;
        }
        else if (n == 3)//cmp XXX,XXX
        {
            if (!(_op == OP_CMP)) break;
        }
        else if (n == 4)//jne @1
        {
            if (!(_disInfo.Branch && _disInfo.Conditional && _b == 'F' && _disInfo.Immediate == _adr1)) break;
            *maxAdr = _maxAdr;
            idr.SetFlag(cfSkip, Adr2Pos(_skipAdr1));
            idr.SetFlag(cfSkip, Adr2Pos(_skipAdr2));
            return _curAdr + _instrLen - fromAdr;
        }
        if (_disInfo.Ret) return 0;
        _curAdr += _instrLen; _curPos += _instrLen;
    }
    return 0;
}
//---------------------------------------------------------------------------
//Check construction not equality ((Int64)val <> XXX)
//cmp XXX,XXX -> set cfSkip (_skipAdr1 = address of this instruction)
//jne @1 -> set cfSkip (_skipAdr2 = address of this instruction)
//cmp XXX,XXX
//je @2
//@1:
int __fastcall Idr64Manager::ProcessInt64NotEquality(DWORD fromAdr, DWORD* maxAdr)
{
    BYTE        _op, _b;
    int         _instrLen, n, _curPos;
    DWORD       _curAdr, _adr1, _adr2, _maxAdr;
    DWORD       _skipAdr1, _skipAdr2;
    DISINFO     _disInfo;

    _curAdr = fromAdr; _curPos = Adr2Pos(_curAdr); _maxAdr = 0;
    for (n = 1; n <= 1024; n++)
    {
        _instrLen = GetDisasm().Disassemble(Code + Adr2Pos(_curAdr), _curAdr, &_disInfo, 0);

        _b = *(Code + _curPos);
        if (_b == 0xF) _b = *(Code + _curPos + 1);
        _b = (_b & 0xF) + 'A';

        _op = GetDisasm().GetOp(_disInfo.MnemIdx);
        if (n == 1)//cmp XXX,XXX
        {
            if (!(_op == OP_CMP)) break;
            _skipAdr1 = _curAdr;
        }
        else if (n == 2)//jne @1
        {
            if (!(_disInfo.Branch && _disInfo.Conditional && _b == 'F')) break;
            _skipAdr2 = _curAdr;
            _adr1 = _disInfo.Immediate;//@1
            if (_adr1 > _maxAdr) _maxAdr = _adr1;
        }
        else if (n == 3)//cmp XXX,XXX
        {
            if (!(_op == OP_CMP)) break;
        }
        else if (n == 4)//je @2
        {
            if (!(_disInfo.Branch && _disInfo.Conditional && _b == 'E' && _curAdr + _instrLen == _adr1)) break;
            _adr2 = _disInfo.Immediate;//@2
            if (_adr2 > _maxAdr) _maxAdr = _adr2;
            *maxAdr = _maxAdr;
            idr.SetFlag(cfSkip, Adr2Pos(_skipAdr1));
            idr.SetFlag(cfSkip, Adr2Pos(_skipAdr2));
            return _curAdr + _instrLen - fromAdr;
        }
        if (_disInfo.Ret) return 0;
        _curAdr += _instrLen; _curPos += _instrLen;
    }
    return 0;
}
//---------------------------------------------------------------------------
//Check construction comparison ((Int64)val >(<) XXX)
//cmp XXX,XXX -> set cfSkip (_skipAdr1 = address of this instruction)
//jxx @1 -> set cfSkip (_skipAdr2 = address of this instruction)
//cmp XXX,XXX
//jxx @@ -> set cfSkip (_skipAdr3 = address of this instruction)
//jmp @@ set cfSkip (_skipAdr4 = address of this instruction)
//@1:jxx @@
int __fastcall Idr64Manager::ProcessInt64Comparison(DWORD fromAdr, DWORD* maxAdr)
{
    BYTE        _op;
    int         _instrLen, n;
    DWORD       _curAdr, _adr, _adr1, _maxAdr;
    DWORD       _skipAdr1, _skipAdr2, _skipAdr3, _skipAdr4;
    DISINFO     _disInfo;

    _curAdr = fromAdr; _maxAdr = 0;
    for (n = 1; n <= 1024; n++)
    {
        _instrLen = GetDisasm().Disassemble(Code + Adr2Pos(_curAdr), _curAdr, &_disInfo, 0);
        _op = GetDisasm().GetOp(_disInfo.MnemIdx);
        if (n == 1)//cmp XXX,XXX
        {
            if (!(_op == OP_CMP)) break;
            _skipAdr1 = _curAdr;
        }
        else if (n == 2)//jxx @1
        {
            if (!(_disInfo.Branch && _disInfo.Conditional)) break;
            _skipAdr2 = _curAdr;
            _adr1 = _disInfo.Immediate;//@1
            if (_adr1 > _maxAdr) _maxAdr = _adr1;
        }
        else if (n == 3)//cmp XXX,XXX
        {
            if (!(_op == OP_CMP)) break;
        }
        else if (n == 4)//jxx @@
        {
            if (!(_disInfo.Branch && _disInfo.Conditional)) break;
            _skipAdr3 = _curAdr;
            _adr = _disInfo.Immediate;//@@
            if (_adr > _maxAdr) _maxAdr = _adr;
        }
        else if (n == 5)//jmp @@
        {
            if (!(_disInfo.Branch && !_disInfo.Conditional)) break;
            _skipAdr4 = _curAdr;
            _adr = _disInfo.Immediate;//@@
            if (_adr > _maxAdr) _maxAdr = _adr;
        }
        else if (n == 6)////@1:jxx @@
        {
            if (!(_disInfo.Branch && _disInfo.Conditional && _curAdr == _adr1)) break;
            _adr = _disInfo.Immediate;//@@
            if (_adr > _maxAdr) _maxAdr = _adr;
            *maxAdr = _maxAdr;
            idr.SetFlag(cfSkip, Adr2Pos(_skipAdr1));
            idr.SetFlag(cfSkip, Adr2Pos(_skipAdr2));
            idr.SetFlag(cfSkip, Adr2Pos(_skipAdr3));
            idr.SetFlag(cfSkip, Adr2Pos(_skipAdr4));
            return  _curAdr + _instrLen - fromAdr;
        }
        if (_disInfo.Ret) return 0;
        _curAdr += _instrLen;
    }
    return 0;
}
//---------------------------------------------------------------------------
//Check construction comparison ((Int64)val >(<) XXX)
//push reg
//push reg
//...
//cmp XXX,[esp+4] (m-th row) set cfSkip (_skipAdr1)
//jxx @1 ->set cfSkip (_skipAdr2)
//cmp XXX,[esp]
//@1:pop reg
//pop reg
//jxx @2
int __fastcall Idr64Manager::ProcessInt64ComparisonViaStack1(DWORD fromAdr, DWORD* maxAdr)
{
    BYTE        _op;
    int         _instrLen, n, m, _skip, _pos;
    DWORD       _curAdr, _adr1, _adr2, _adr3, _maxAdr, _pushAdr;
    DWORD       _skipAdr1, _skipAdr2;
    DISINFO     _disInfo;

    _curAdr = fromAdr; m = -1; _maxAdr = 0;
    for (n = 1; n <= 1024; n++)
    {
        _instrLen = GetDisasm().Disassemble(Code + Adr2Pos(_curAdr), _curAdr, &_disInfo, 0);
        _op = GetDisasm().GetOp(_disInfo.MnemIdx);
        if (n == 1)//push reg
        {
            if (!(_op == OP_PUSH && _disInfo.OpType[0] == otREG)) break;
        }
        else if (n == 2)//push reg
        {
            if (!(_op == OP_PUSH && _disInfo.OpType[0] == otREG)) break;
            _pushAdr = _curAdr;
        }
        else if (n >= 3 && m == -1 && _op == OP_CMP && _disInfo.OpType[1] == otMEM && _disInfo.BaseReg == 20 && _disInfo.Offset == 4)//cmp XXX,[esp+4]
        {
            //Find nearest up instruction "push reg"
            _pos = Adr2Pos(_curAdr);
            while (1)
            {
                _pos--;
                if (_pos == fromAdr) break;
                if (IsFlagSet(cfInstruction, _pos))
                {
                    GetDisasm().Disassemble(Code + _pos, Pos2Adr(_pos), &_disInfo, 0);
                    _op = GetDisasm().GetOp(_disInfo.MnemIdx);
                    if (_op == OP_PUSH) break;
                }
            }
            if (Pos2Adr(_pos) != _pushAdr) return 0;
            m = n;
            _skipAdr1 = _curAdr;
        }
        else if (m != -1 && n == m + 1)//jxx @1
        {
            if (!(_disInfo.Branch && _disInfo.Conditional)) break;
            _skipAdr2 = _curAdr;
            _adr1 = _disInfo.Immediate;//@1
            if (_adr1 > _maxAdr) _maxAdr = _adr1;
        }
        else if (m != -1 && n == m + 2)//cmp XXX,[esp]
        {
            if (!(_op == OP_CMP && _disInfo.OpType[1] == otMEM && _disInfo.BaseReg == 20 && _disInfo.Offset == 0)) break;
        }
        else if (m != -1 && n == m + 3)//@1:pop reg
        {
            if (!(_op == OP_POP && _disInfo.OpType[0] == otREG && _curAdr == _adr1)) break;
        }
        else if (m != -1 && n == m + 4)//pop reg
        {
            if (!(_op == OP_POP && _disInfo.OpType[0] == otREG)) break;
        }
        else if (m != -1 && n == m + 5)//jxx @2
        {
            if (!(_disInfo.Branch && _disInfo.Conditional)) break;
            *maxAdr = _maxAdr;
            idr.SetFlag(cfSkip, Adr2Pos(_skipAdr1));
            idr.SetFlag(cfSkip, Adr2Pos(_skipAdr2));
            return  _curAdr + _instrLen - fromAdr;
        }
        if (m == -1 && (_disInfo.Ret || _disInfo.Branch)) return 0;
        _curAdr += _instrLen;
    }
    return 0;
}
//---------------------------------------------------------------------------
//Check construction comparison ((Int64)val >(<) XXX)
//push reg
//push reg
//...
//cmp XXX,[esp+4] (m-th row) set cfSkip (_skipAdr1)
//jxx @1 ->set cfSkip (_skipAdr2)
//cmp XXX,[esp]
//pop reg ->set cfSkip (_skipAdr3)
//pop reg ->set cfSkip (_skipAdr4)
//jxx @@ ->set cfSkip (_skipAdr5)
//jmp @@ ->set cfSkip (_skipAdr6)
//@1:
//pop reg
//pop reg
//jxx @2
int __fastcall Idr64Manager::ProcessInt64ComparisonViaStack2(DWORD fromAdr, DWORD* maxAdr)
{
    BYTE        _op;
    int         _instrLen, n, m, _skip, _pos;
    DWORD       _curAdr, _adr, _adr1, _adr2, _maxAdr, _pushAdr;
    DWORD       _skipAdr1, _skipAdr2, _skipAdr3, _skipAdr4, _skipAdr5, _skipAdr6;
    DISINFO     _disInfo;

    _curAdr = fromAdr; m = -1; _maxAdr = 0;
    for (n = 1; n <= 1024; n++)
    {
        _instrLen = GetDisasm().Disassemble(Code + Adr2Pos(_curAdr), _curAdr, &_disInfo, 0);
        _op = GetDisasm().GetOp(_disInfo.MnemIdx);
        if (n == 1)//push reg
        {
            if (!(_op == OP_PUSH && _disInfo.OpType[0] == otREG)) break;
        }
        else if (n == 2)//push reg
        {
            if (!(_op == OP_PUSH && _disInfo.OpType[0] == otREG)) break;
            _pushAdr = _curAdr;
        }
        else if (n >= 3 && m == -1 && _op == OP_CMP && _disInfo.OpType[1] == otMEM && _disInfo.BaseReg == 20 && _disInfo.Offset == 4)//cmp XXX,[esp+4]
        {
            //Find nearest up instruction "push reg"
            _pos = Adr2Pos(_curAdr);
            while (1)
            {
                _pos--;
                if (_pos == fromAdr) break;
                if (IsFlagSet(cfInstruction, _pos))
                {
                    GetDisasm().Disassemble(Code + _pos, Pos2Adr(_pos), &_disInfo, 0);
                    _op = GetDisasm().GetOp(_disInfo.MnemIdx);
                    if (_op == OP_PUSH) break;
                }
            }
            if (Pos2Adr(_pos) != _pushAdr) return 0;
            m = n;
            _skipAdr1 = _curAdr;
        }
        else if (m != -1 && n == m + 1)//jxx @1
        {
            if (!(_disInfo.Branch && _disInfo.Conditional)) break;
            _skipAdr2 = _curAdr;
            _adr1 = _disInfo.Immediate;//@1
            if (_adr1 > _maxAdr) _maxAdr = _adr1;
        }
        else if (m != -1 && n == m + 2)//cmp XXX,[esp]
        {
            if (!(_op == OP_CMP && _disInfo.OpType[1] == otMEM && _disInfo.BaseReg == 20 && _disInfo.Offset == 0)) break;
        }
        else if (m != -1 && n == m + 3)//pop reg
        {
            if (!(_op == OP_POP && _disInfo.OpType[0] == otREG)) break;
            _skipAdr3 = _curAdr;
        }
        else if (m != -1 && n == m + 4)//pop reg
        {
            if (!(_op == OP_POP && _disInfo.OpType[0] == otREG)) break;
            _skipAdr4 = _curAdr;
        }
        else if (m != -1 && n == m + 5)//jxx @@
        {
            if (!(_disInfo.Branch && _disInfo.Conditional)) break;
            _skipAdr5 = _curAdr;
            _adr = _disInfo.Immediate;//@3
            if (_adr > _maxAdr) _maxAdr = _adr;
        }
        else if (m != -1 && n == m + 6)//jmp @@
        {
            if (!(_disInfo.Branch && !_disInfo.Conditional)) break;
            _skipAdr6 = _curAdr;
            _adr = _disInfo.Immediate;//@2
            if (_adr > _maxAdr) _maxAdr = _adr;
        }
        else if (m != -1 && n == m + 7)//@1:pop reg
        {
            if (!(_op == OP_POP && _disInfo.OpType[0] == otREG && _curAdr == _adr1)) break;
        }
        else if (m != -1 && n == m + 8)//pop reg
        {
            if (!(_op == OP_POP && _disInfo.OpType[0] == otREG)) break;
        }
        else if (m != -1 && n == m + 9)//jxx @2
        {
            if (!(_disInfo.Branch && _disInfo.Conditional)) break;
            _adr2 = _disInfo.Immediate;
            if (_adr2 > _maxAdr) _maxAdr = _adr2;
            *maxAdr = _maxAdr;
            idr.SetFlag(cfSkip, Adr2Pos(_skipAdr1));
            idr.SetFlag(cfSkip, Adr2Pos(_skipAdr2));
            idr.SetFlag(cfSkip, Adr2Pos(_skipAdr3));
            idr.SetFlag(cfSkip, Adr2Pos(_skipAdr4));
            idr.SetFlag(cfSkip, Adr2Pos(_skipAdr5));
            idr.SetFlag(cfSkip, Adr2Pos(_skipAdr6));
            return  _curAdr + _instrLen - fromAdr;
        }
        if (m == -1 && (_disInfo.Ret || _disInfo.Branch)) return 0;
        _curAdr += _instrLen;
    }
    return 0;
}
//---------------------------------------------------------------------------
//Check construction equality ((Int64)val = XXX)
//cmp XXX,XXX
//jne @1 (_br1Adr = address of this instruction)
//cmp XXX,XXX ->skip1 up to this instruction
//jne @1 -> skip2 up to this instruction, Result = skip2
//...
//@1:... -> delete 1 xRef to this instruction (address = _adr1)
int __fastcall Idr64Manager::IsInt64Equality(DWORD fromAdr, int* skip1, int* skip2, bool *immVal, __int64* Val)
{
    bool        _imm;
    BYTE        _op, _b;
    int         _instrLen, n, _curPos, _skip;
    DWORD       _curAdr, _adr1, _br1Adr;
    DISINFO     _disInfo;
    __int64     _val1, _val2;
    //PInfoRec    _recN;

    _curAdr = fromAdr; _curPos = Adr2Pos(_curAdr); _imm = false;
    for (n = 1; n <= 1024; n++)
    {
        _instrLen = GetDisasm().Disassemble(Code + Adr2Pos(_curAdr), _curAdr, &_disInfo, 0);

        _b = *(Code + _curPos);
        if (_b == 0xF) _b = *(Code + _curPos + 1);
        _b = (_b & 0xF) + 'A';

        _op = GetDisasm().GetOp(_disInfo.MnemIdx);
        if (n == 1)//cmp XXX,XXX
        {
            if (!(_op == OP_CMP)) break;
            if (_disInfo.OpType[1] == otIMM)
            {
                _imm = true;
                _val1 = _disInfo.Immediate;
            }
        }
        else if (n == 2)//jne @1
        {
            if (!(_disInfo.Branch && _disInfo.Conditional && _b == 'F')) break;
            _br1Adr = _curAdr;
            _adr1 = _disInfo.Immediate;//@1
        }
        else if (n == 3)//cmp XXX,XXX
        {
            if (!(_op == OP_CMP)) break;
            *skip1 = _curAdr - fromAdr;
            if (_disInfo.OpType[1] == otIMM)
            {
                _imm = true;
                _val2 = _disInfo.Immediate;
            }
        }
        else if (n == 4)//jne @1
        {
            if (!(_disInfo.Branch && _disInfo.Conditional && _b == 'F' && _disInfo.Immediate == _adr1)) break;
            _skip = _curAdr - fromAdr;
            *skip2 = _skip;
            *immVal = _imm;
            if (_imm) *Val = (_val1 << 32) | _val2;
            return _skip;
        }
        if (_disInfo.Ret) return 0;
        _curAdr += _instrLen; _curPos += _instrLen;
    }
    return 0;
}
//---------------------------------------------------------------------------
//Check construction not equality ((Int64)val <> XXX)
//cmp XXX,XXX
//jne @1 (_br1Adr = address of this instruction)
//cmp XXX,XXX ->skip1 up to this instruction
//je @2 -> skip2 up to this instruction, Result = skip2
//@1:... -> delete 1 xRef to this instruction (address = _adr1)
int __fastcall Idr64Manager::IsInt64NotEquality(DWORD fromAdr, int* skip1, int* skip2, bool *immVal, __int64* Val)
{
    bool        _imm;
    BYTE        _op, _b;
    int         _instrLen, n, _curPos, _skip;
    DWORD       _curAdr, _adr1, _adr2, _br1Adr;
    DISINFO     _disInfo;
    __int64     _val1, _val2;
    //PInfoRec    _recN;

    _curAdr = fromAdr; _curPos = Adr2Pos(_curAdr); _imm = false;
    for (n = 1; n <= 1024; n++)
    {
        _instrLen = GetDisasm().Disassemble(Code + Adr2Pos(_curAdr), _curAdr, &_disInfo, 0);

        _b = *(Code + _curPos);
        if (_b == 0xF) _b = *(Code + _curPos + 1);
        _b = (_b & 0xF) + 'A';

        _op = GetDisasm().GetOp(_disInfo.MnemIdx);
        if (n == 1)//cmp XXX,XXX
        {
            if (!(_op == OP_CMP)) break;
            if (_disInfo.OpType[1] == otIMM)
            {
                _imm = true;
                _val1 = _disInfo.Immediate;
            }
        }
        else if (n == 2)//jne @1
        {
            if (!(_disInfo.Branch && _disInfo.Conditional && _b == 'F')) break;
            _br1Adr = _curAdr;
            _adr1 = _disInfo.Immediate;//@1
        }
        else if (n == 3)//cmp XXX,XXX
        {
            if (!(_op == OP_CMP)) break;
            *skip1 = _curAdr - fromAdr;
            if (_disInfo.OpType[1] == otIMM)
            {
                _imm = true;
                _val2 = _disInfo.Immediate;
            }
        }
        else if (n == 4)//je @2
        {
            if (!(_disInfo.Branch && _disInfo.Conditional && _b == 'E' && _curAdr + _instrLen == _adr1)) break;
            _skip = _curAdr - fromAdr;
            *skip2 = _skip;
            *immVal = _imm;
            if (_imm) *Val = (_val1 << 32) | _val2;
            return _skip;
        }
        if (_disInfo.Ret) return 0;
        _curAdr += _instrLen; _curPos += _instrLen;
    }
    return 0;
}
//---------------------------------------------------------------------------
//Check construction comparison ((Int64)val >(<) XXX)
//cmp XXX,XXX
//jxx @1 (_br1Adr = address of this instruction)
//cmp XXX,XXX ->skip1 up to this instruction
//jxx @@ (_br3Adr = address of this instruction)
//jmp @@ (_br2Adr = address of this instruction)
//@1:jxx @@ (skip2 up to this instruction, Result = skip2)
int __fastcall Idr64Manager::IsInt64Comparison(DWORD fromAdr, int* skip1, int* skip2, bool* immVal, __int64* Val)
{
    bool        _imm;
    BYTE        _op;
    int         _instrLen, n, m, _skip;
    __int64     _val1, _val2;
    DWORD       _curAdr, _adr1, _br1Adr, _br2Adr, _br3Adr;
    DISINFO     _disInfo;
    //PInfoRec    _recN;

    _curAdr = fromAdr; _imm = false;
    for (n = 1; n <= 1024; n++)
    {
        _instrLen = GetDisasm().Disassemble(Code + Adr2Pos(_curAdr), _curAdr, &_disInfo, 0);
        _op = GetDisasm().GetOp(_disInfo.MnemIdx);
        if (n == 1)//cmp XXX,XXX
        {
            if (!(_op == OP_CMP)) break;
            if (_disInfo.OpType[1] == otIMM)
            {
                _imm = true;
                _val1 = _disInfo.Immediate;
            }
        }
        else if (n == 2)//jxx @1
        {
            if (!(_disInfo.Branch && _disInfo.Conditional)) break;
            _br1Adr = _curAdr;
            _adr1 = _disInfo.Immediate;//@1
        }
        else if (n == 3)//cmp XXX,XXX
        {
            if (!(_op == OP_CMP)) break;
            *skip1 = _curAdr - fromAdr;
            if (_disInfo.OpType[1] == otIMM)
            {
                _imm = true;
                _val2 = _disInfo.Immediate;
            }
        }
        else if (n == 4)//jxx @@
        {
            if (!(_disInfo.Branch && _disInfo.Conditional)) break;
            _br3Adr = _curAdr;
        }
        else if (n == 5)//jmp @@
        {
            if (!(_disInfo.Branch && !_disInfo.Conditional)) break;
            _br2Adr = _curAdr;
        }
        else if (n == 6)////@1:jxx @@
        {
            if (!(_disInfo.Branch && _disInfo.Conditional && _curAdr == _adr1)) break;
            _skip = _curAdr - fromAdr;
            *skip2 = _skip;
            *immVal = _imm;
            if (_imm) *Val = (_val1 << 32) | _val2;
            return _skip;
        }
        if (_disInfo.Ret) return 0;
        _curAdr += _instrLen;
    }
    return 0;
}
//---------------------------------------------------------------------------
//Check construction comparison ((Int64)val >(<) N)
//push reg
//push reg
//...
//cmp XXX,[esp+4] (m-th row) ->Simulate upto this address
//jxx @1
//cmp XXX,[esp] ->skip1=this position
//@1:pop reg
//pop reg
//jxx @@ ->Result
int __fastcall Idr64Manager::IsInt64ComparisonViaStack1(DWORD fromAdr, int* skip1, DWORD* simEnd)
{
    BYTE        _op;
    int         _instrLen, n, m, _pos;
    DWORD       _curAdr = fromAdr, _adr1, _pushAdr;
    DISINFO     _disInfo;

    _curAdr = fromAdr; *skip1 = 0; *simEnd = 0; m = -1;
    for (n = 1; n <= 1024; n++)
    {
        _instrLen = GetDisasm().Disassemble(Code + Adr2Pos(_curAdr), _curAdr, &_disInfo, 0);
        _op = GetDisasm().GetOp(_disInfo.MnemIdx);
        if (n == 1)//push reg
        {
            if (!(_op == OP_PUSH && _disInfo.OpType[0] == otREG)) break;
        }
        else if (n == 2)//push reg
        {
            if (!(_op == OP_PUSH && _disInfo.OpType[0] == otREG)) break;
            _pushAdr = _curAdr;
        }
        else if (n >= 3 && m == -1 && _op == OP_CMP && _disInfo.OpType[1] == otMEM && _disInfo.BaseReg == 20 && _disInfo.Offset == 4)//cmp XXX,[esp+4]
        {
            //Find nearest up instruction "push reg"
            _pos = Adr2Pos(_curAdr);
            while (1)
            {
                _pos--;
                if (_pos == fromAdr) break;
                if (IsFlagSet(cfInstruction, _pos))
                {
                    GetDisasm().Disassemble(Code + _pos, Pos2Adr(_pos), &_disInfo, 0);
                    _op = GetDisasm().GetOp(_disInfo.MnemIdx);
                    if (_op == OP_PUSH) break;
                }
            }
            if (Pos2Adr(_pos) != _pushAdr) return 0;
            m = n;
            *simEnd = _curAdr;
        }
        else if (m != -1 && n == m + 1)//jxx @1
        {
            if (!(_disInfo.Branch && _disInfo.Conditional)) break;
            _adr1 = _disInfo.Immediate;//@1
        }
        else if (m != -1 && n == m + 2)//cmp XXX,[esp]
        {
            if (!(_op == OP_CMP && _disInfo.OpType[1] == otMEM && _disInfo.BaseReg == 20 && _disInfo.Offset == 0)) break;
            *skip1 = _curAdr - fromAdr;
        }
        else if (m != -1 && n == m + 3)//pop reg
        {
            if (!(_op == OP_POP && _disInfo.OpType[0] == otREG && _curAdr == _adr1)) break;
        }
        else if (m != -1 && n == m + 4)//pop reg
        {
            if (!(_op == OP_POP && _disInfo.OpType[0] == otREG)) break;
        }
        else if (m != -1 && n == m + 5)//jxx @@
        {
            if (!(_disInfo.Branch && _disInfo.Conditional)) break;
            return  _curAdr - fromAdr;
        }
        if (m == -1 && (_disInfo.Ret || _disInfo.Branch)) return 0;
        _curAdr += _instrLen;
    }
    return 0;
}
//---------------------------------------------------------------------------
//Check construction comparison ((Int64)val >(<) XXX)
//push reg
//push reg
//...
//cmp XXX,[esp+4] (m-th row) ->Simulate upto this address
//jxx @1
//cmp XXX,[esp] ->skip1=this position
//pop reg
//pop reg
//jxx @@ ->skip2
//jmp @@
//@1:
//pop reg
//pop reg
//jxx @@ ->Result
int __fastcall Idr64Manager::IsInt64ComparisonViaStack2(DWORD fromAdr, int* skip1, int* skip2, DWORD* simEnd)
{
    BYTE        _op;
    int         _instrLen, n, m, _pos;
    DWORD       _curAdr = fromAdr, _adr1, _pushAdr;
    DISINFO     _disInfo;

    _curAdr = fromAdr; *simEnd = 0; m = -1;
    for (n = 1; n <= 1024; n++)
    {
        _instrLen = GetDisasm().Disassemble(Code + Adr2Pos(_curAdr), _curAdr, &_disInfo, 0);
        _op = GetDisasm().GetOp(_disInfo.MnemIdx);
        if (n == 1)//push reg
        {
            if (!(_op == OP_PUSH && _disInfo.OpType[0] == otREG)) break;
        }
        else if (n == 2)//push reg
        {
            if (!(_op == OP_PUSH && _disInfo.OpType[0] == otREG)) break;
            _pushAdr = _curAdr;
        }
        else if (n >= 3 && m == -1 && _op == OP_CMP && _disInfo.OpType[1] == otMEM && _disInfo.BaseReg == 20 && _disInfo.Offset == 4)//cmp XXX,[esp+4]
        {
            //Find nearest up instruction "push reg"
            _pos = Adr2Pos(_curAdr);
            while (1)
            {
                _pos--;
                if (_pos == fromAdr) break;
                if (IsFlagSet(cfInstruction, _pos))
                {
                    GetDisasm().Disassemble(Code + _pos, Pos2Adr(_pos), &_disInfo, 0);
                    _op = GetDisasm().GetOp(_disInfo.MnemIdx);
                    if (_op == OP_PUSH) break;
                }
            }
            if (Pos2Adr(_pos) != _pushAdr) return 0;
            m = n;
            *simEnd = _curAdr;
        }
        else if (m != -1 && n == m + 1)//jxx @1
        {
            if (!(_disInfo.Branch && _disInfo.Conditional)) break;
            _adr1 = _disInfo.Immediate;//@1
        }
        else if (m != -1 && n == m + 2)//cmp XXX,[esp]
        {
            if (!(_op == OP_CMP && _disInfo.OpType[1] == otMEM && _disInfo.BaseReg == 20 && _disInfo.Offset == 0)) break;
            *skip1 = _curAdr - fromAdr;
        }
        else if (m != -1 && n == m + 3)//pop reg
        {
            if (!(_op == OP_POP && _disInfo.OpType[0] == otREG)) break;
        }
        else if (m != -1 && n == m + 4)//pop reg
        {
            if (!(_op == OP_POP && _disInfo.OpType[0] == otREG)) break;
        }
        else if (m != -1 && n == m + 5)//jxx @@
        {
            if (!(_disInfo.Branch && _disInfo.Conditional)) break;
            *skip2 = _curAdr - fromAdr;
        }
        else if (m != -1 && n == m + 6)//jmp @@
        {
            if (!(_disInfo.Branch && !_disInfo.Conditional)) break;
        }
        else if (m != -1 && n == m + 7)//@1:pop reg
        {
            if (!(_op == OP_POP && _disInfo.OpType[0] == otREG && _curAdr == _adr1)) break;
        }
        else if (m != -1 && n == m + 8)//pop reg
        {
            if (!(_op == OP_POP && _disInfo.OpType[0] == otREG)) break;
        }
        else if (m != -1 && n == m + 9)//jxx @@
        {
            if (!(_disInfo.Branch && _disInfo.Conditional)) break;
            return  _curAdr - fromAdr;
        }
        if (m == -1 && (_disInfo.Ret || _disInfo.Branch)) return 0;
        _curAdr += _instrLen;
    }
    return 0;
}
//---------------------------------------------------------------------------
//Check construction
//shrd reg1,reg2,N
//shr reg2,N
int __fastcall Idr64Manager::IsInt64Shr(DWORD fromAdr)
{
    BYTE        _op;
    int         _instrLen, n, _idx, _val;
    DWORD       _curAdr = fromAdr;
    DISINFO     _disInfo;

    for (n = 1; n <= 2; n++)
    {
        _instrLen = GetDisasm().Disassemble(Code + Adr2Pos(_curAdr), _curAdr, &_disInfo, 0);
        _op = GetDisasm().GetOp(_disInfo.MnemIdx);
        if (n == 1)
        {
            if (!(_op == OP_SHR && _disInfo.OpNum == 3 && _disInfo.OpType[0] == otREG && _disInfo.OpType[1] == otREG && _disInfo.OpType[2] == otIMM)) break;
            _idx = _disInfo.OpRegIdx[1];
            _val = _disInfo.Immediate;
        }
        else if (n == 2)
        {
            if (!(_op == OP_SHR && _disInfo.OpNum == 2 && _disInfo.OpType[0] == otREG && _disInfo.OpType[1] == otIMM && _disInfo.OpRegIdx[0] == _idx && _disInfo.Immediate == _val)) break;
            return _curAdr + _instrLen - fromAdr;
        }
        if (_disInfo.Ret) return 0;
        _curAdr += _instrLen;
    }
    return 0;
}
//---------------------------------------------------------------------------
//Check construction
//shld reg1,reg2,N
//shl reg2,N
int __fastcall Idr64Manager::IsInt64Shl(DWORD fromAdr)
{
    BYTE        _op;
    int         _instrLen, n, _idx, _val;
    DWORD       _curAdr = fromAdr;
    DISINFO     _disInfo;

    for (n = 1; n <= 2; n++)
    {
        _instrLen = GetDisasm().Disassemble(Code + Adr2Pos(_curAdr), _curAdr, &_disInfo, 0);
        _op = GetDisasm().GetOp(_disInfo.MnemIdx);
        if (n == 1)
        {
            if (!(_op == OP_SHL && _disInfo.OpNum == 3 && _disInfo.OpType[0] == otREG && _disInfo.OpType[1] == otREG && _disInfo.OpType[2] == otIMM)) break;
            _idx = _disInfo.OpRegIdx[1];
            _val = _disInfo.Immediate;
        }
        else if (n == 2)
        {
            if (!(_op == OP_SHL && _disInfo.OpNum == 2 && _disInfo.OpType[0] == otREG && _disInfo.OpType[2] == otIMM && _disInfo.OpRegIdx[0] == _idx &&_disInfo.Immediate == _val)) break;
            return _curAdr + _instrLen - fromAdr;
        }
        if (_disInfo.Ret) return 0;
        _curAdr += _instrLen;
    }
    return 0;
}
//---------------------------------------------------------------------------

//---------------------------------------------------------------------------
PFIELDINFO __fastcall GetField(String TypeName, int Offset, bool* vmt, DWORD* vmtAdr)
{
    BYTE        scope;
    int         n, idx, kind, size, Ofs;
    DWORD       classAdr;
    BYTE        *p;
    WORD        *uses, Len;
    MTypeInfo   atInfo;
    MTypeInfo   *tInfo = &atInfo;
    PFIELDINFO	fInfo, fInfo1, fInfo2;

    *vmt = false; *vmtAdr = 0;
    classAdr = GetClassAdr(TypeName);
    if (IsValidImageAdr(classAdr))
    {
        *vmt = true; *vmtAdr = classAdr; 
        DWORD prevClassAdr = 0;
    	while (classAdr && Offset < GetClassSize(classAdr))
        {
        	prevClassAdr = classAdr;
        	classAdr = GetParentAdr(classAdr);
        }
        classAdr = prevClassAdr;

        if (classAdr)
        {
            PInfoRec recN = GetInfoRec(classAdr);
            if (recN && recN->vmtInfo && recN->vmtInfo->fields)
            {
                if (recN->vmtInfo->fields->Count == 1)
                {
                    fInfo = (PFIELDINFO)recN->vmtInfo->fields->Items[0];
                    if (Offset == fInfo->Offset)
                    {
                        *vmtAdr = classAdr;
                        return fInfo;
                    }
                    return 0;
                }
                for (int n = 0; n < recN->vmtInfo->fields->Count - 1; n++)
                {
                    fInfo1 = (PFIELDINFO)recN->vmtInfo->fields->Items[n];
                    fInfo2 = (PFIELDINFO)recN->vmtInfo->fields->Items[n + 1];
                    if (Offset >= fInfo1->Offset && Offset < fInfo2->Offset)
                    {
                        if (Offset == fInfo1->Offset)
                        {
                            *vmtAdr = classAdr;
                            return fInfo1;
                        }
                        kind = GetTypeKind(fInfo1->Type, &size);
                        if (kind == ikRecord || kind == ikArray)
                        {
                            *vmtAdr = classAdr;
                            return fInfo1;
                        }
                    }
                }
                fInfo = (PFIELDINFO)recN->vmtInfo->fields->Items[recN->vmtInfo->fields->Count - 1];
                if (Offset >= fInfo->Offset)
                {
                    if (Offset == fInfo->Offset)
                    {
                        *vmtAdr = classAdr;
                        return fInfo;
                    }
                    kind = GetTypeKind(fInfo->Type, &size);
                    if (kind == ikRecord || kind == ikArray)
                    {
                        *vmtAdr = classAdr;
                        return fInfo;
                    }
                }
            }
        }
        return 0;
    }

    //try KB
    uses = KnowledgeBase.GetTypeUses(TypeName.c_str());
    idx = KnowledgeBase.GetTypeIdxByModuleIds(uses, TypeName.c_str());
    if (uses) delete[] uses;

    if (idx != -1)
    {
    	fInfo = 0;
        idx = KnowledgeBase.TypeOffsets[idx].NamId;
        if (KnowledgeBase.GetTypeInfo(idx, INFO_FIELDS, tInfo))
        if (tInfo->Fields)
        {
            p = tInfo->Fields;
            for (n = 0; n < tInfo->FieldsNum; n++)
            {
                //Scope
                scope = *p; p++;
                //offset
                Ofs = *((int*)p); p += 4;
                if (Ofs == Offset)
                {
                	fInfo = new FIELDINFO;
                    fInfo->Scope = scope;
                    fInfo->Case = *((int*)p); p += 4;
                    fInfo->xrefs = 0;
                    Len = *((WORD*)p); p += 2;
                    fInfo->Name = String((char*)p, Len); p += Len + 1;
                    Len = *((WORD*)p); p += 2;
                    fInfo->Type = TrimTypeName(String((char*)p, Len));
                    break;
                }
                else
                {
                    p += 4;
                    Len = *((WORD*)p); p += 2;
                    p += Len + 1;
                    Len = *((WORD*)p); p += 2;
                    p += Len + 1;
                }
            }
            return fInfo;
        }
    }
    return 0;
}
//---------------------------------------------------------------------------
PFIELDINFO __fastcall AddField(DWORD ProcAdr, int ProcOfs, String TypeName, BYTE Scope, int Offset, int Case, String Name, String Type)
{
    DWORD classAdr = GetClassAdr(TypeName);
    if (IsValidImageAdr(classAdr))
    {
    	if (Offset < 4) return 0;

    	DWORD prevClassAdr = 0;
    	while (classAdr && Offset < GetClassSize(classAdr))
        {
        	prevClassAdr = classAdr;
        	classAdr = GetParentAdr(classAdr);
        }
        classAdr = prevClassAdr;

        if (classAdr)
        {
            PInfoRec recN = GetInfoRec(classAdr);
            if (!recN) return 0;
            if (!recN->vmtInfo) return 0;
            return recN->vmtInfo->AddField(ProcAdr, ProcOfs, Scope, Offset, Case, Name, Type);
        }
    }
    return 0;
}
//---------------------------------------------------------------------------
String __fastcall MakeComment(PPICODE Picode)
{
    bool	vmt;
    DWORD	vmtAdr;
	String	comment = "";

    if (Picode->Op == OP_CALL || Picode->Op == OP_COMMENT)
    {
    	comment = Picode->Name;
    }
    else
    {
        PFIELDINFO fInfo = GetField(Picode->Name, Picode->Ofs.Offset, &vmt, &vmtAdr);
        if (fInfo)
        {
            comment = Picode->Name + ".";
            if (fInfo->Name == "")
                comment += "?f" + Val2Str0(Picode->Ofs.Offset);
            else
                comment += fInfo->Name;
            comment += ":";
            if (fInfo->Type == "")
                comment += "?";
            else
                comment += TrimTypeName(fInfo->Type);

            if (!vmt) delete fInfo;
        }
        else if (Picode->Name != "")
        {
            comment = Picode->Name + ".?f" + Val2Str0(Picode->Ofs.Offset) + ":?";
        }
    }
    return comment;
}


TCriticalSection* GetSyncObj()
{
    static TCriticalSection* CrtSection;
    if (!CrtSection) CrtSection = new TCriticalSection();
    return CrtSection;
}


MDisasm& GetDisasm()
{
    static MDisasm Disasm(GetSyncObj());//Дизассемблер для анализатора кода
    return Disasm;
}

//---------------------------------------------------------------------------
void Idr64Manager::CleanProject()
{
    int         n;
    PInfoRec    recN;

    if (Image)
    {
        delete[] Image;
        Image = 0;
    }

    if (Flags)
    {
        delete[] Flags;
        Flags = 0;
    }

    if (Infos)
    {
        for (n = 0; n < TotalSize; n++)
        {
            recN = GetInfoRec(Pos2Adr(n));
            if (recN) delete recN;
        }
        delete[] Infos;
        Infos = 0;
    }
    if (BSSInfos)
    {
        for (n = 0; n < BSSInfos->Count; n++)
        {
            recN = (PInfoRec)BSSInfos->Objects[n];
            if (recN) delete recN;
        }

        delete BSSInfos;
        BSSInfos = 0;
    }

    if (SegmentList)
    {
        for (n = 0; n < SegmentList->Count; n++)
        {
            PSegmentInfo segInfo = (PSegmentInfo)SegmentList->Items[n];
            delete segInfo;
        }
        SegmentList->Clear();
    }

    if (VmtList)
        VmtList->Clear();

    if (Units)
    {
        for (n = 0; n < UnitsNum; n++)
        {
            PUnitRec recU = (PUnitRec)Units->Items[n];
            delete recU;
        }
        Units->Clear();
    }
    UnitsNum = 0;

    if (OwnTypeList)
    {
        for (n = 0; n < OwnTypeList->Count; n++)
        {
            PTypeRec recT = (PTypeRec)OwnTypeList->Items[n];
            delete recT;
        }
        OwnTypeList->Clear();
    }
}


//---------------------------------------------------------------------------
bool __fastcall Idr64Manager::IsFlagSet(DWORD flag, int pos)
{
//!!!
if (pos < 0 || pos >= TotalSize)
{
  dummy = 1;
  return false;
}
    assert(pos >= 0 && pos < TotalSize);
    return (Flags[pos] & flag);
}
//---------------------------------------------------------------------------
void __fastcall Idr64Manager::SetFlag(DWORD flag, int pos)
{
//!!!
if (pos < 0 || pos >= TotalSize)
{
  dummy = 1;
  return;
}
    assert(pos >= 0 && pos < TotalSize);
    Flags[pos] |= flag;
}
//---------------------------------------------------------------------------
void __fastcall Idr64Manager::SetFlags(DWORD flag, int pos, int num)
{
//!!!
if (pos < 0 || pos + num >= TotalSize)
{
dummy = 1;
return;
}
    assert(pos >= 0 && (pos + num < TotalSize));
    for (int i = pos; i < pos + num; i++)
    {
        Flags[i] |= flag;
    }
}
//---------------------------------------------------------------------------
void __fastcall Idr64Manager::ClearFlag(DWORD flag, int pos)
{
//!!!
if (pos < 0 || pos >= TotalSize)
{
  dummy = 1;
  return;
}
    assert(pos >= 0 && pos < TotalSize);
    Flags[pos] &= ~flag;
}
//---------------------------------------------------------------------------
void __fastcall Idr64Manager::ClearFlags(DWORD flag, int pos, int num)
{
if (pos < 0 || pos + num > TotalSize)
{
dummy = 1;
return;
}
    assert(pos >= 0 && (pos + num < TotalSize));
    for (int i = pos; i < pos + num; i++)
    {
        Flags[i] &= ~flag;
    }
}

bool __fastcall Idr64Manager::IsFlagEmpty(int pos)
{
    assert(pos >= 0 && pos < TotalSize);
    return (!Flags[pos]);
}

void __fastcall Idr64Manager::XorFlag(DWORD Val, int pos)
{
    assert(pos >= 0 && pos < TotalSize);
    Flags[pos] ^= Val;
}

//---------------------------------------------------------------------------
int __fastcall GetSegmentNo(DWORD Adr)
{
    for (int n = 0; n < SegmentList->Count; n++)
    {
        PSegmentInfo segInfo = (PSegmentInfo)SegmentList->Items[n];
        if (segInfo->Start <= Adr && Adr < segInfo->Start + segInfo->Size) return n;
    }
    return -1;
}

//---------------------------------------------------------------------------
//Возвращает "высоту" класса (число родительских классов до 0)
int __fastcall GetClassHeight(DWORD adr)
{
    int level = 0;
    while (1)
    {
        adr = GetParentAdr(adr);
        if (!adr) break;
        level++;
    }

    return level;
}

//---------------------------------------------------------------------------
//Возвращает общий родительский тип для типов Name1, Name2
String __fastcall GetCommonType(String Name1, String Name2)
{
	if (SameText(Name1, Name2)) return Name1;
    
	DWORD adr1 = GetClassAdr(Name1);
    DWORD adr2 = GetClassAdr(Name2);
    //Synonims
    if (!adr1 || !adr2)
    {
        //dword and ClassName -> ClassName
        if (SameText(Name1, "Dword") && IsValidImageAdr(GetClassAdr(Name2))) return Name2;
        if (SameText(Name2, "Dword") && IsValidImageAdr(GetClassAdr(Name1))) return Name1;
        //UString - UnicodeString
        if ((SameText(Name1, "UString") && SameText(Name2, "UnicodeString")) ||
            (SameText(Name1, "UnicodeString") && SameText(Name2, "UString"))) return "UnicodeString";
    	//String - AnsiString
    	if ((SameText(Name1, "String") && SameText(Name2, "AnsiString")) ||
        	(SameText(Name1, "AnsiString") && SameText(Name2, "String"))) return "AnsiString";
        //Text - TTextRec
        if ((SameText(Name1, "Text") && SameText(Name2, "TTextRec")) ||
        	(SameText(Name1, "TTextRec") && SameText(Name2, "Text"))) return "TTextRec";
        return "";
    }
    
	int h1 = GetClassHeight(adr1);
    int h2 = GetClassHeight(adr2);

    while (h1 != h2)
    {
    	if (h1 > h2)
        {
        	adr1 = GetParentAdr(adr1);
            h1--;
        }
        else
        {
        	adr2 = GetParentAdr(adr2);
            h2--;
        }
    }

    while (adr1 != adr2)
    {
    	adr1 = GetParentAdr(adr1);
        adr2 = GetParentAdr(adr2);
    }

    return GetClsName(adr1);
}


//---------------------------------------------------------------------------
bool __fastcall IsUnitExist(String Name)
{
    for (int n = 0; n < UnitsNum; n++)
    {
        PUnitRec recU = (PUnitRec)Units->Items[n];
        if (recU->names->IndexOf(Name) != -1) return true;
    }
    return false;
}
//---------------------------------------------------------------------------
PUnitRec __fastcall GetUnit(DWORD Adr)
{
    PUnitRec  _res=0;
    DataGuard dg(GetSyncObj());

    for (int n = 0; n < UnitsNum; n++)
    {
        PUnitRec recU = (PUnitRec)Units->Items[n];
        if (Adr >= recU->fromAdr && Adr < recU->toAdr) _res = recU;
    }

    return _res;
}
//---------------------------------------------------------------------------
String __fastcall GetUnitName(PUnitRec recU)
{
    if (recU)
    {
        if (recU->names->Count == 1)
            return recU->names->Strings[0];
        else
            return "_Unit" + String(recU->iniOrder);
    }
    return "";
}
//---------------------------------------------------------------------------
String __fastcall GetUnitName(DWORD Adr)
{
    int     n;
    String  Result = "";

    PUnitRec recU = GetUnit(Adr);
    if (recU)
    {
        for (n = 0; n < recU->names->Count; n++)
        {
            if (n) Result += ", ";
            Result += recU->names->Strings[n];
        }
    }
    return Result;
}
//---------------------------------------------------------------------------
void __fastcall SetUnitName(PUnitRec recU, String name)
{
    if (recU && recU->names->IndexOf(name) == -1)
        recU->names->Add(name);
}
//---------------------------------------------------------------------------
bool __fastcall InOneUnit(DWORD Adr1, DWORD Adr2)
{
    for (int n = 0; n < UnitsNum; n++)
    {
        PUnitRec recU = (PUnitRec)Units->Items[n];
        if (Adr1 >= recU->fromAdr && Adr1 < recU->toAdr &&
            Adr2 >= recU->fromAdr && Adr2 < recU->toAdr) return true;
    }
    return false;
}


//---------------------------------------------------------------------------
int __fastcall EstimateProcSize(DWORD fromAdr)
{
    BYTE        op;
    int         row, num, instrLen, instrLen1, instrLen2, Pos;
    int         fromPos = Adr2Pos(fromAdr);
    int         curPos = fromPos;
    DWORD       curAdr = fromAdr;
    DWORD       lastAdr = 0;
    DWORD       Adr, Adr1, lastMovAdr = 0;
    PInfoRec    recN;
    DISINFO     DisInfo;

    if (idr.IsFlagSet(cfImport, fromPos))
    {
        return GetDisasm().Disassemble(Code + fromPos, (__int64)fromAdr, &DisInfo, 0);
    }

    if (idr.IsFlagSet(cfExcInfo, fromPos))
    {
        for (int pos = fromPos; pos < TotalSize; pos++)
        {
            if (idr.IsFlagSet(cfProcEnd, pos))
            {
                return pos - fromPos;
            }
        }
    }

    for (row = 0; row < MAX_DISASSEMBLE; row++)
    {
        BYTE b1 = Code[curPos];
        BYTE b2 = Code[curPos + 1];
        if (!b1 && !b2 && !lastAdr) break;

        instrLen = GetDisasm().Disassemble(Code + curPos, (__int64)curAdr, &DisInfo, 0);
        //if (!instrLen) break;
        if (!instrLen)  //If obfuscated program
        {
            curPos++; curAdr++;
            continue;
        }
        //Code
        idr.SetFlags(cfCode, curPos, instrLen);
        //Instruction begin
        idr.SetFlag(cfInstruction, curPos);

        op = GetDisasm().GetOp(DisInfo.MnemIdx);

        if (curAdr >= lastAdr) lastAdr = 0;

        if (op == OP_JMP)
        {
            if (curAdr == fromAdr)
            {
                curAdr += instrLen;
                break;
            }
            if (DisInfo.OpType[0] == otMEM)
            {
                if (Adr2Pos(DisInfo.Offset) < 0 && (!lastAdr || curAdr == lastAdr))
                {
                    curAdr += instrLen;
                    break;
                }
            }
            if (DisInfo.OpType[0] == otIMM)
            {
                Adr = DisInfo.Immediate;
                if (Adr2Pos(Adr) < 0 && (!lastAdr || curAdr == lastAdr))
                {
                    curAdr += instrLen;
                    break;
                }
                if (GetSegmentNo(Adr) != 0 && GetSegmentNo(fromAdr) != GetSegmentNo(Adr) && (!lastAdr || curAdr == lastAdr))
                {
                    curAdr += instrLen;
                    break;
                }
                if (Adr < fromAdr && (!lastAdr || curAdr == lastAdr))
                {
                    curAdr += instrLen;
                    break;
                }
            }
        }
        //End of procedure
        if (DisInfo.Ret)// && (!lastAdr || curAdr == lastAdr))
        {
            if (!idr.IsFlagSet(cfLoc, Pos + instrLen))
            {
                curAdr += instrLen;
                break;
            }
        }

        if (op == OP_MOV) lastMovAdr = DisInfo.Offset;

        if (DisInfo.Branch && instrLen == 2)    //Short relative abs jmp or cond jmp
        {
            Adr = DisInfo.Immediate;
            if (IsValidImageAdr(Adr))
            {
                idr.SetFlag(cfLoc, Adr2Pos(Adr));
                if (Adr >= fromAdr && Adr > lastAdr) lastAdr = Adr;
            }
            curPos += instrLen; curAdr += instrLen;
            continue;
        }
        if (DisInfo.Branch && instrLen == 5)    //Relative abs jmp or cond jmp
        {
            Adr = DisInfo.Immediate;
            if (IsValidImageAdr(Adr))
            {
                idr.SetFlag(cfLoc, Adr2Pos(Adr));
                recN = GetInfoRec(Adr);
                if (!recN && Adr >= fromAdr && Adr > lastAdr) lastAdr = Adr;
            }
            curPos += instrLen; curAdr += instrLen;
            continue;
        }
        if (DisInfo.Call)
        {
            Adr = DisInfo.Immediate; Pos = Adr2Pos(Adr);
            if (IsValidImageAdr(Adr))
            {
                if (Pos >= 0)
                {
                    idr.SetFlag(cfLoc, Pos);
                    recN = GetInfoRec(Adr);
                    if (recN && recN->SameName("@Halt0"))
                    {
                        if (fromAdr == EP && !lastAdr) break;
                    }
                }
            }
        }
        curPos += instrLen; curAdr += instrLen;
    }
    return curAdr - fromAdr;
}
//---------------------------------------------------------------------------
//Check possibility of "straping" procedure (only at the first level)
bool __fastcall StrapCheck(int pos, MProcInfo* ProcInfo)
{
    int         _ap;
    String      name, fName, _key;
    PInfoRec    recN;

    if (!ProcInfo) return false;

    BYTE *dump = ProcInfo->Dump;
    //Fixup data begin
    BYTE *p = dump + 2*(ProcInfo->DumpSz);
    //If procedure is jmp off_XXXXXXXX, return false
    if (*dump == 0xFF && *(dump + 1) == 0x25) return false;

    FIXUPINFO fixupInfo;
    for (int n = 0; n < ProcInfo->FixupNum; n++)
    {
        fixupInfo.Type = *p; p++;
        fixupInfo.Ofs = *((DWORD*)p); p += 4;
        WORD Len = *((WORD*)p); p += 2;
        fixupInfo.Name = p; p += Len + 1;

        String fName = String(fixupInfo.Name);
        //Fixupname begins with "_Dn_" - skip it
        if (fName.Pos("_Dn_") == 1) continue;
        //Fixupname begins with "_NF_" - skip it
        if (fName.Pos("_NF_") == 1) continue;
        //Fixupname is "_DV_" - skip it
        if (SameText(fName, "_DV_")) continue;
        //Fixupname begins with "_DV_"
        if (fName.Pos("_DV_") == 1)
        {
            char c = fName[5];
            //Fixupname is _DV_number - skip it
            if (c >= '0' && c <= '9') continue;
            //Else transfrom fixupname to normal
            if (fName[Len] == '_')
                fName = fName.SubString(5, Len - 5);
            else
                fName = fName.SubString(5, Len - 4);
        }
        //Empty fixupname - skip it
        if (fName == "") continue;

        DWORD Adr, Ofs, Val = *((DWORD*)(Code + pos + fixupInfo.Ofs));
        if (fixupInfo.Type == 'A' || fixupInfo.Type == 'S')
        {
            Ofs = *((DWORD*)(dump + fixupInfo.Ofs));
            Adr = Val - Ofs;
            if (IsValidImageAdr(Adr))
            {
                _ap = Adr2Pos(Adr); recN = GetInfoRec(Adr);
                if (recN && recN->HasName())
                {
                    //If not import call just compare names
                    if (_ap >= 0 && !idr.IsFlagSet(cfImport, _ap))
                    {
                        if (!recN->SameName(fName)) return false;
                    }
                    //Else may be partial unmatching
                    else
                    {
                        name = ExtractProcName(recN->GetName());
                        if (!SameText(name, fName) && !SameText(name.SubString(1, name.Length() - 1), fName))
                            return false;
                    }
                }
            }
        }
        else if (fixupInfo.Type == 'J')
        {
            Adr = CodeBase + pos + fixupInfo.Ofs + 4 + Val;
            if (IsValidCodeAdr(Adr))
            {
                _ap = Adr2Pos(Adr); recN = GetInfoRec(Adr);
                if (recN && recN->HasName())
                {
                    //If not import call just compare names
                    if (_ap >= 0 && !idr.IsFlagSet(cfImport, _ap))
                    {
                        if (!recN->SameName(fName)) return false;
                    }
                    //Else may be partial unmatching
                    else
                    {
                        name = ExtractProcName(recN->GetName());
                        if (!SameText(name, fName))
                        {
                            String name1 = name.SubString(1, name.Length() - 1);//Trim last symbol ('A','W') - GetWindowLongW(A)
                            if (!SameText(fName.SubString(1, name1.Length()), name1)) return false;
                        }
                    }
                }
            }
        }
        else if (fixupInfo.Type == 'D')
        {
            Adr = Val;
            if (IsValidImageAdr(Adr))
            {
                recN = GetInfoRec(Adr);
                if (recN && recN->HasName())
                {
                    if (!recN->SameName(fName)) return false;
                }
            }
        }
    }
    return true;
}
//---------------------------------------------------------------------------
//"Strap" procedure ProcIdx int code from position pos
void __fastcall StrapProc(int pos, int ProcIdx, MProcInfo* ProcInfo, bool useFixups, int procSize)
{
    if (!ProcInfo) return;
    #if 0 //TODO
    //Citadel!!!
	if (SameText(ProcInfo->ProcName, "CtdReg"))
    {
    	if (procSize == 1) return;
        CtdRegAdr = Pos2Adr(pos);
    }
    #endif
    
    DWORD ProcStart = Pos2Adr(pos);
    DWORD ProcEnd = ProcStart + procSize;

    String ModuleName = KnowledgeBase.GetModuleName(ProcInfo->ModuleID);
    if (!IsUnitExist(ModuleName))
    {
        //Get unit by pos
        PUnitRec recU = GetUnit(Pos2Adr(pos));
        if (recU)
        {
            SetUnitName(recU, ModuleName);
            recU->kb = true;
        }
    }
    BYTE* p; PInfoRec recN;
    if (ProcInfo->DumpType == 'D')
    {
    	idr.SetFlags(cfData, pos, procSize);
    }
    else
    {
        idr.SetFlags(cfCode, pos, procSize);
        //Mark proc begin
        idr.SetFlag(cfProcStart, pos);
        idr.SetFlag(cfProcEnd, pos + procSize);

        recN = GetInfoRec(Pos2Adr(pos));
        if (!recN) recN = new InfoRec(pos, ikRefine);
        //Mark proc end
        recN->procInfo->procSize = procSize;

        switch (ProcInfo->MethodKind)
        {
        case 'C':
            recN->kind = ikConstructor;
            break;
        case 'D':
            recN->kind = ikDestructor;
            break;
        case 'F':
            recN->kind = ikFunc;
            recN->type = ProcInfo->TypeDef;
            break;
        case 'P':
            recN->kind = ikProc;
            break;
        }

        recN->kbIdx = ProcIdx;
        recN->SetName(ProcInfo->ProcName);
        //Get Args
        if (!recN->MakeArgsManually())
        {
            BYTE callKind = ProcInfo->CallKind;
            recN->procInfo->flags |= callKind;

            int aa = 0, ss = 8;
            ARGINFO argInfo;
            p = ProcInfo->Args;
            if (p)
            {
                for (int k = 0; k < ProcInfo->ArgsNum; k++)
                {
                    argInfo.Tag = *p; p++;
                    int locflags = *((int*)p); p += 4;

                    if ((locflags & 7) == 1) argInfo.Tag = 0x23;  //Add by ZGL

                    argInfo.Register = (locflags & 8);
                    //Ndx
                    int ndx = *((int*)p); p += 4;

                    argInfo.Size = 4;
                    WORD wlen = *((WORD*)p); p += 2;
                    argInfo.Name = String((char*)p, wlen); p += wlen + 1;
                    wlen = *((WORD*)p); p += 2;
                    argInfo.TypeDef = TrimTypeName(String((char*)p, wlen)); p += wlen + 1;
                    //Some correction of knowledge base
                    if (SameText(argInfo.Name, "Message") && SameText(argInfo.TypeDef, "void"))
                    {
                        argInfo.Name = "Msg";
                        argInfo.TypeDef = "TMessage";
                    }

                    if (SameText(argInfo.TypeDef, "String")) argInfo.TypeDef = "AnsiString";
                    if (SameText(argInfo.TypeDef, "Int64")    ||
                        SameText(argInfo.TypeDef, "Real")     ||
                        SameText(argInfo.TypeDef, "Real48")   ||
                        SameText(argInfo.TypeDef, "Comp")     ||
                        SameText(argInfo.TypeDef, "Double")   ||
                        SameText(argInfo.TypeDef, "Currency") ||
                        SameText(argInfo.TypeDef, "TDateTime"))
                        argInfo.Size = 8;
                    if (SameText(argInfo.TypeDef, "Extended")) argInfo.Size = 12;

                    if (!callKind)
                    {
                        if (aa < 3 && argInfo.Size == 4)
                        {
                            argInfo.Ndx = aa;
                            aa++;
                        }
                        else
                        {
                            argInfo.Ndx = ss;
                            ss += argInfo.Size;
                        }
                    }
                    else
                    {
                        argInfo.Ndx = ss;
                        ss += argInfo.Size;
                    }
                    recN->procInfo->AddArg(&argInfo);
                }
            }
        }
        recN->procInfo->flags |= PF_KBPROTO;
    }
    //Fix used procedure
    KnowledgeBase.SetUsedProc(ProcIdx);

    if (useFixups && ProcInfo->FixupNum)
    {
        //Get array of used modules
        int Idx, size;
        WORD *uses = KnowledgeBase.GetModuleUses(ProcInfo->ModuleID);
        //Начало данных по фиксапам
        p = ProcInfo->Dump + 2*ProcInfo->DumpSz;
        FIXUPINFO fixupInfo;

        MConstInfo acInfo;
        MConstInfo *cInfo = &acInfo;
        MTypeInfo  atInfo;
        MTypeInfo *tInfo = &atInfo;
        MVarInfo  avInfo;
        MVarInfo  *vInfo = &avInfo;
        MResStrInfo arsInfo;
        MResStrInfo *rsInfo = &arsInfo;
        MProcInfo aInfo; MProcInfo* pInfo = &aInfo;
        DWORD Adr, Adr1, Ofs, Val;
        WORD Len;
        String fName;

        for (int n = 0; n < ProcInfo->FixupNum; n++)
        {
            fixupInfo.Type = *p; p++;
            fixupInfo.Ofs = *((DWORD*)p); p += 4;
            Len = *((WORD*)p); p += 2;
            fixupInfo.Name = p; p += Len + 1;
            fName = String(fixupInfo.Name, Len);
            //Fixupname begins with _Dn_ - skip it
            if (fName.Pos("_Dn_") == 1) continue;
            //Fixupname begins with _NF_ - skip it
            if (fName.Pos("_NF_") == 1) continue;
            //Fixupname is "_DV_" - skip it
            if (SameText(fName, "_DV_")) continue;
            //Fixupname begins with _DV_
            if (fName.Pos("_DV_") == 1)
            {
                char c = fName[5];
                //Fixupname is _DV_number - skip it
                if (c >= '0' && c <= '9') continue;
                //Else transfrom fixupname to normal
                if (fName[Len] == '_')
                    fName = fName.SubString(5, Len - 5);
                else
                    fName = fName.SubString(5, Len - 4);
            }
            if (fName == "" || fName == ".") continue;

            Val = *((DWORD*)(Code + pos + fixupInfo.Ofs));
            //FixupName is the same as ProcName
            if (SameText(fName, ProcInfo->ProcName))
            {
                //!!!
                //Need to use this information:
                //CaseStudio, 405ae4 - call [offs+4*eax] - how to use offs? And offs has cfLoc
                //Val inside procedure - possible jump address for switch (or call)
                if (fixupInfo.Type == 'J')
                {
                    Adr = CodeBase + pos + fixupInfo.Ofs + Val + 4;
                    if (Adr >= ProcStart && Adr < ProcEnd)
                        idr.SetFlag(cfLoc | cfEmbedded, Adr2Pos(Adr));
                }
                continue;
            }
            //Сначала подсчитаем адрес, а потом будем пытаться определять секцию
            if (fixupInfo.Type == 'A' || fixupInfo.Type == 'S' || fixupInfo.Type == '4' || fixupInfo.Type == '8')
            {
                //Смотрим, какая величина стоит в дампе в позиции фиксапа
                Ofs = *((DWORD*)(ProcInfo->Dump + fixupInfo.Ofs));
                Adr   = Val - Ofs;
            }
            else if (fixupInfo.Type == 'J')
            {
                Adr = CodeBase + pos + fixupInfo.Ofs + Val + 4;
            }
            else if (fixupInfo.Type == 'D' || fixupInfo.Type == '6' || fixupInfo.Type == '5')
            {
                Adr = Val;
            }
            else if (fixupInfo.Type == 'G')
            {
                continue;//??? Don't know yet
            }
            else if (fixupInfo.Type == 'E')
            {
                continue;//??? Don't know yet
            }
            else
            {
                ShowMessage("Unknown fixup type: " + String(fixupInfo.Type));
                continue;
            }

            bool isHInstance = (stricmp(fixupInfo.Name, "HInstance") == 0);
            if (!IsValidImageAdr(Adr))
            {
                //Пока здесь наблюдались лишь одни ThreadVars и TlsLast
                if (!stricmp(fixupInfo.Name, "TlsLast"))
                {
                    LastTls = Val;
                }
                else
                {
                    recN = GetInfoRec(Pos2Adr(pos + fixupInfo.Ofs));
                    if (!recN)
                    {
                        recN = new InfoRec(pos + fixupInfo.Ofs, ikData);
                        recN->SetName(fixupInfo.Name);
                        //Определим тип Var
                        Idx = KnowledgeBase.GetVarIdx(uses, fixupInfo.Name);
                        if (Idx != -1)
                        {
                            Idx = KnowledgeBase.VarOffsets[Idx].NamId;
                            if (KnowledgeBase.GetVarInfo(Idx, 0, vInfo))
                            {
                                if (vInfo->Type == 'T')
                                    recN->kind = ikThreadVar;
                                recN->kbIdx = Idx;
                                recN->type = TrimTypeName(vInfo->TypeDef);
                            }
                        }
                    }
                }
                continue;
            }
        
            if (Adr >= ProcStart && Adr < ProcEnd) continue;

            if (isHInstance)
            {
                Adr1 = *((DWORD*)(Code + Adr2Pos(Adr)));
                if (IsValidImageAdr(Adr1))
                    HInstanceVarAdr = Adr1;
                else
                    HInstanceVarAdr = Adr;
            }

            int Sections = KnowledgeBase.GetItemSection(uses, fixupInfo.Name);
            //Адрес в кодовом сегменте вне тела самой функции
            if (IsValidCodeAdr(Adr))
            {
                recN = GetInfoRec(Adr);
                if (!recN)
                {
                    switch (Sections)
                    {
                    case KB_CONST_SECTION:
                        Idx = KnowledgeBase.GetConstIdx(uses, fixupInfo.Name);
                        if (Idx != -1)
                        {
                            Idx = KnowledgeBase.ConstOffsets[Idx].NamId;
                            //Если имя начинается на _DV_, значит это VMT
                            if (!memcmp(fixupInfo.Name, "_DV_", 4))
                            {
                                if (KnowledgeBase.GetConstInfo(Idx, INFO_DUMP, cInfo))
                                    StrapVMT(Adr2Pos(Adr) + 4, Idx, cInfo);
                            }
                            else
                            {
                            }
                        }
                        break;
                    case KB_TYPE_SECTION:
                        Idx = KnowledgeBase.GetTypeIdxByModuleIds(uses, fixupInfo.Name);
                        if (Idx != -1)
                        {
                            Idx = KnowledgeBase.TypeOffsets[Idx].NamId;
                            if (KnowledgeBase.GetTypeInfo(Idx, 0, tInfo))
                            {
                                recN = new InfoRec(Adr2Pos(Adr), ikData);
                                recN->kbIdx = Idx;
                                recN->SetName(tInfo->TypeName);
                            }
                        }
                        break;
                    case KB_VAR_SECTION:
                        Idx = KnowledgeBase.GetVarIdx(uses, fixupInfo.Name);
                        if (Idx != -1)
                        {
                            Idx = KnowledgeBase.VarOffsets[Idx].NamId;
                            if (KnowledgeBase.GetVarInfo(Idx, 0, vInfo))
                            {
                                recN = new InfoRec(Adr2Pos(Adr), ikData);
                                recN->kbIdx = Idx;
                                recN->SetName(vInfo->VarName);
                                recN->type = TrimTypeName(vInfo->TypeDef);
                            }
                        }
                        break;
                    case KB_RESSTR_SECTION:
                        Idx = KnowledgeBase.GetResStrIdx(uses, fixupInfo.Name);
                        if (Idx != -1)
                        {
                            Idx = KnowledgeBase.ResStrOffsets[Idx].NamId;
                            if (KnowledgeBase.GetResStrInfo(Idx, 0, rsInfo))
                            {
                                recN = new InfoRec(Adr2Pos(Adr), ikData);
                                recN->kbIdx = Idx;
                                recN->SetName(rsInfo->ResStrName);
                                recN->type = rsInfo->TypeDef;
                            }
                        }
                        break;
                    case KB_PROC_SECTION:
                        Idx = KnowledgeBase.GetProcIdx(uses, fixupInfo.Name, Code + Adr2Pos(Adr));
                        if (Idx != -1)
                        {
                            Idx = KnowledgeBase.ProcOffsets[Idx].NamId;
                            if (!KnowledgeBase.IsUsedProc(Idx))
                            {
                                if (KnowledgeBase.GetProcInfo(Idx, INFO_DUMP | INFO_ARGS, pInfo))
                                    StrapProc(Adr2Pos(Adr), Idx, pInfo, true, pInfo->DumpSz);
                            }
                        }
                        else
                        {
                            Idx = KnowledgeBase.GetProcIdx(uses, fixupInfo.Name, 0);
                            if (Idx != -1)
                            {
                                Idx = KnowledgeBase.ProcOffsets[Idx].NamId;
                                if (!KnowledgeBase.IsUsedProc(Idx))
                                {
                                    if (KnowledgeBase.GetProcInfo(Idx, INFO_DUMP | INFO_ARGS, pInfo))
                                    {
                                        if (!SameText(fName, "@Halt"))
                                        {
                                            StrapProc(Adr2Pos(Adr), Idx, pInfo, false, EstimateProcSize(Adr));
                                        }
                                        else
                                        {
                                            DISINFO _disInfo;
                                            int _bytes = EstimateProcSize(Adr);
                                            while (_bytes > 0)
                                            {
                                                int _instrlen = GetDisasm().Disassemble(Code + Adr2Pos(Adr), (__int64)Adr, &_disInfo, 0);
                                                if (_disInfo.Branch && !_disInfo.Conditional)
                                                {
                                                    Adr = _disInfo.Immediate;
                                                    Idx = KnowledgeBase.GetProcIdx(uses, "@Halt0", 0);
                                                    if (Idx != -1)
                                                    {
                                                        Idx = KnowledgeBase.ProcOffsets[Idx].NamId;
                                                        if (!KnowledgeBase.IsUsedProc(Idx))
                                                        {
                                                            if (KnowledgeBase.GetProcInfo(Idx, INFO_DUMP | INFO_ARGS, pInfo))
                                                                StrapProc(Adr2Pos(Adr), Idx, pInfo, false, EstimateProcSize(Adr));
                                                        }
                                                    }
                                                    break;
                                                }
                                                _bytes -= _instrlen;
                                            }
                                        }
                                    }
                                }
                            }

                        }
                        break;
                    }
                    continue;
                }
            }
            //Адрес в секции DATA
            if (IsValidImageAdr(Adr))
            {
                int _pos = Adr2Pos(Adr);
                if (_pos >= 0)
                {
                    recN = GetInfoRec(Adr);
                    if (!recN)
                    {
                        switch (Sections)
                        {
                        case KB_CONST_SECTION:
                            Idx = KnowledgeBase.GetConstIdx(uses, fixupInfo.Name);
                            if (Idx != -1)
                            {
                                Idx = KnowledgeBase.ConstOffsets[Idx].NamId;
                                if (KnowledgeBase.GetConstInfo(Idx, INFO_DUMP, cInfo))
                                {
                                    String cname = "";
                                    if (cInfo->ConstName.Pos("_DV_") == 1)
                                    {
                                        char c = cInfo->ConstName[5];
                                        if (c > '9')
                                        {
                                            if (cInfo->ConstName[Len] == '_')
                                                cname = cInfo->ConstName.SubString(5, Len - 5);
                                            else
                                                cname = cInfo->ConstName.SubString(5, Len - 4);
                                        }
                                    }
                                    else
                                        cname = cInfo->ConstName;

                                    recN = new InfoRec(_pos, ikData);
                                    recN->kbIdx = Idx;
                                    recN->SetName(cname);
                                    recN->type = cInfo->TypeDef;
                                }
                            }
                            break;
                        case KB_TYPE_SECTION:
                            Idx = KnowledgeBase.GetTypeIdxByModuleIds(uses, fixupInfo.Name);
                            if (Idx != -1)
                            {
                                Idx = KnowledgeBase.TypeOffsets[Idx].NamId;
                                if (KnowledgeBase.GetTypeInfo(Idx, 0, tInfo))
                                {
                                    recN = new InfoRec(_pos, ikData);
                                    recN->kbIdx = Idx;
                                    recN->SetName(tInfo->TypeName);
                                }
                            }
                            break;
                        case KB_VAR_SECTION:
                            Idx = KnowledgeBase.GetVarIdx(uses, fixupInfo.Name);
                            if (Idx != -1)
                            {
                                Idx = KnowledgeBase.VarOffsets[Idx].NamId;
                                if (KnowledgeBase.GetVarInfo(Idx, 0, vInfo))
                                {
                                    recN = new InfoRec(_pos, ikData);
                                    recN->kbIdx = Idx;
                                    recN->SetName(vInfo->VarName);
                                    recN->type = TrimTypeName(vInfo->TypeDef);
                                }
                            }
                            break;
                        case KB_RESSTR_SECTION:
                            Idx = KnowledgeBase.GetResStrIdx(uses, fixupInfo.Name);
                            if (Idx != -1)
                            {
                                Idx = KnowledgeBase.ResStrOffsets[Idx].NamId;
                                if (KnowledgeBase.GetResStrInfo(Idx, 0, rsInfo))
                                {
                                    recN = new InfoRec(_pos, ikData);
                                    recN->kbIdx = Idx;
                                    recN->SetName(rsInfo->ResStrName);
                                    recN->type = rsInfo->TypeDef;
                                }
                            }
                            break;
                        }
                    }
                }
                else
                {
                    switch (Sections)
                    {
                    case KB_CONST_SECTION:
                        Idx = KnowledgeBase.GetConstIdx(uses, fixupInfo.Name);
                        if (Idx != -1)
                        {
                            Idx = KnowledgeBase.ConstOffsets[Idx].NamId;
                            if (KnowledgeBase.GetConstInfo(Idx, INFO_DUMP, cInfo))
                            {
                                String cname = "";
                                if (cInfo->ConstName.Pos("_DV_") == 1)
                                {
                                    char c = cInfo->ConstName[5];
                                    if (c > '9')
                                    {
                                        if (cInfo->ConstName[Len] == '_')
                                            cname = cInfo->ConstName.SubString(5, Len - 5);
                                        else
                                            cname = cInfo->ConstName.SubString(5, Len - 4);
                                    }
                                }
                                else
                                    cname = cInfo->ConstName;

                                idr.AddToBSSInfos(Adr, cname, cInfo->TypeDef);
                            }
                        }
                        break;
                    case KB_TYPE_SECTION:
                        Idx = KnowledgeBase.GetTypeIdxByModuleIds(uses, fixupInfo.Name);
                        if (Idx != -1)
                        {
                            Idx = KnowledgeBase.TypeOffsets[Idx].NamId;
                            if (KnowledgeBase.GetTypeInfo(Idx, 0, tInfo))
                            {
                                idr.AddToBSSInfos(Adr, tInfo->TypeName, "");
                            }
                        }
                        break;
                    case KB_VAR_SECTION:
                        Idx = KnowledgeBase.GetVarIdx(uses, fixupInfo.Name);
                        if (Idx != -1)
                        {
                            Idx = KnowledgeBase.VarOffsets[Idx].NamId;
                            if (KnowledgeBase.GetVarInfo(Idx, 0, vInfo))
                            {
                                idr.AddToBSSInfos(Adr, vInfo->VarName, TrimTypeName(vInfo->TypeDef));
                            }
                        }
                        break;
                    case KB_RESSTR_SECTION:
                        Idx = KnowledgeBase.GetResStrIdx(uses, fixupInfo.Name);
                        if (Idx != -1)
                        {
                            Idx = KnowledgeBase.ResStrOffsets[Idx].NamId;
                            if (KnowledgeBase.GetResStrInfo(Idx, 0, rsInfo))
                            {
                                idr.AddToBSSInfos(Adr, rsInfo->ResStrName, rsInfo->TypeDef);
                            }
                        }
                        break;
                    }
                }
            }
        }
        if (uses) delete[] uses;
    }
}

//---------------------------------------------------------------------------
//"Вшивает" VMT в код с позиции pos
void __fastcall StrapVMT(int pos, int ConstId, MConstInfo* ConstInfo)
{
    if (!ConstInfo) return;

    //Check dump VMT
    BYTE *dump = ConstInfo->Dump;
    BYTE *relocs = ConstInfo->Dump + ConstInfo->DumpSz;
    bool match = true;
    for (int n = 0; n < ConstInfo->DumpSz; n++)
    {
        if (relocs[n] != 0xFF && Code[pos + n] != dump[n])
        {
            match = false;
            break;
        }
    }
    if (!match) return;

    idr.SetFlags(cfData , pos, ConstInfo->DumpSz);

    int Idx, Pos, VMTOffset = Vmt.SelfPtr;
    //"Strap" fixups
    //Get used modules array
    WORD *uses = KnowledgeBase.GetModuleUses(ConstInfo->ModuleID);
    //Begin fixups data
    BYTE *p = ConstInfo->Dump + 2*(ConstInfo->DumpSz);
    FIXUPINFO fixupInfo;
    MProcInfo aInfo; MProcInfo* pInfo = &aInfo;
    for (int n = 0; n < ConstInfo->FixupNum; n++)
    {
        fixupInfo.Type = *p; p++;
        fixupInfo.Ofs = *((DWORD*)p); p += 4;
        WORD Len = *((WORD*)p); p += 2;
        fixupInfo.Name = p; p += Len + 1;
        //Name begins with _D - skip it
        if (fixupInfo.Name[0] == '_' && fixupInfo.Name[1] == 'D') continue;
        //In VMT all fixups has type 'A'
        DWORD Adr = *((ULONGLONG*)(Code + pos + fixupInfo.Ofs));

        VMTOffset = Vmt.SelfPtr + fixupInfo.Ofs;

        if (VMTOffset == Vmt.IntfTable)
        {
            //if (IsValidCodeAdr(Adr) && !Infos[Adr2Pos(Adr)])
            if (!idr.GetInfos(Adr))
            {
                //Strap IntfTable
                Idx = KnowledgeBase.GetProcIdx(ConstInfo->ModuleID, fixupInfo.Name, Code + Adr2Pos(Adr));
                if (Idx != -1)
                {
                    Idx = KnowledgeBase.ProcOffsets[Idx].NamId;
                    if (!KnowledgeBase.IsUsedProc(Idx))
                    {
                        if (KnowledgeBase.GetProcInfo(Idx, INFO_DUMP | INFO_ARGS, pInfo))
                        {
                            StrapProc(Adr2Pos(Adr), Idx, pInfo, true, pInfo->DumpSz);
                        }
                    }
                }
            }
            continue;
        }
        if (VMTOffset == Vmt.AutoTable)
        {
            //Strap AutoTable
            //Unknown - no examples
            continue;
        }
        if (VMTOffset == Vmt.InitTable)
        {
            //InitTable is table of pointers to types, that will be processed later
            continue;
        }
        if (VMTOffset == Vmt.TypeInfo)
        {
            //Already processed, skip it
            continue;
        }
        if (VMTOffset == Vmt.FieldTable)
        {
            //Skip because fields will be processed later
            continue;
        }
        if (VMTOffset == Vmt.MethodTable)
        {
            //Skip because mrthods will be processed later
            continue;
        }
        if (VMTOffset == Vmt.DynamicTable)
        {
            //Skip because dynamics will be processed later
            continue;
        }
        if (VMTOffset == Vmt.ClassName)
        {
            //ClassName skip
            continue;
        }
        if (VMTOffset == Vmt.Parent)
        {
            //Points to parent class, skip it because it will processed later
            continue;
        }
        if (VMTOffset >= Vmt.Parent && VMTOffset <= Vmt.Destroy)
        {
            //if (IsValidCodeAdr(Adr) && !Infos[Adr2Pos(Adr)])
            if (!idr.GetInfos(Adr))
            {
                Idx = KnowledgeBase.GetProcIdx(uses, fixupInfo.Name, Code + Adr2Pos(Adr));
                if (Idx != -1)
                {
                    Idx = KnowledgeBase.ProcOffsets[Idx].NamId;
                    if (!KnowledgeBase.IsUsedProc(Idx))
                    {
                        if (KnowledgeBase.GetProcInfo(Idx, INFO_DUMP | INFO_ARGS, pInfo))
                        {
                            StrapProc(Adr2Pos(Adr), Idx, pInfo, true, pInfo->DumpSz);
                        }
                    }
                }
                //Code not matched, but prototype may be used
                else
                {
                    PInfoRec recN = new InfoRec(Adr2Pos(Adr), ikRefine);
                    recN->SetName(fixupInfo.Name);
                    //Prototype???
                    if (uses)
                    {
                        for (int m = 0; uses[m] != 0xFFFF; m++)
                        {
                            Idx = KnowledgeBase.GetProcIdx(uses[m], fixupInfo.Name);
                            if (Idx != -1)
                            {
                                Idx = KnowledgeBase.ProcOffsets[Idx].NamId;
                                if (KnowledgeBase.GetProcInfo(Idx, INFO_ARGS, pInfo))
                                {
                                    switch (pInfo->MethodKind)
                                    {
                                    case 'C':
                                        recN->kind = ikConstructor;
                                        break;
                                    case 'D':
                                        recN->kind = ikDestructor;
                                        break;
                                    case 'P':
                                        recN->kind = ikProc;
                                        break;
                                    case 'F':
                                        recN->kind = ikFunc;
                                        recN->type = pInfo->TypeDef;
                                        break;
                                    }

                                    if (pInfo->Args)
                                    {
                                    	BYTE callKind = pInfo->CallKind;
                                        recN->procInfo->flags |= callKind;

                                        ARGINFO argInfo; BYTE *pp = pInfo->Args; int ss = 8;
                                        for (int k = 0; k < pInfo->ArgsNum; k++)
                                        {
                                            FillArgInfo(k, callKind, &argInfo, &pp, &ss);
                                            recN->procInfo->AddArg(&argInfo);
                                        }
                                    }
                                    //Set kbIdx for fast search
                                    recN->kbIdx = Idx;
                                    recN->procInfo->flags |= PF_KBPROTO;
                                }
                            }
                        }
                    }
                }
            }
            continue;
        }
        //If address in code segment and has no recN
        //if (IsValidCodeAdr(Adr) && !Infos[Adr2Pos(Adr)])
        if (!idr.GetInfos(Adr))
        {
            //RTTI?
            if (!idr.IsFlagSet(cfRTTI, Adr2Pos(Adr)))
            {
                //Procedure?
                Idx = KnowledgeBase.GetProcIdx(uses, fixupInfo.Name, Code + Adr2Pos(Adr));
                if (Idx != -1)
                {
                    Idx = KnowledgeBase.ProcOffsets[Idx].NamId;
                    if (!KnowledgeBase.IsUsedProc(Idx))
                    {
                        if (KnowledgeBase.GetProcInfo(Idx, INFO_DUMP | INFO_ARGS, pInfo))
                        {
                            StrapProc(Adr2Pos(Adr), Idx, pInfo, true, pInfo->DumpSz);
                        }
                    }
                }
                //Code not matched, but prototype may be used
                else
                {
                    PInfoRec recN = new InfoRec(Adr2Pos(Adr), ikRefine);
                    recN->SetName(fixupInfo.Name);
                    //Prototype???
                    if (uses)
                    {
                        for (int m = 0; uses[m] != 0xFFFF; m++)
                        {
                            Idx = KnowledgeBase.GetProcIdx(uses[m], fixupInfo.Name);
                            if (Idx != -1)
                            {
                                Idx = KnowledgeBase.ProcOffsets[Idx].NamId;
                                if (KnowledgeBase.GetProcInfo(Idx, INFO_ARGS, pInfo))
                                {
                                    switch (pInfo->MethodKind)
                                    {
                                    case 'C':
                                        recN->kind = ikConstructor;
                                        break;
                                    case 'D':
                                        recN->kind = ikDestructor;
                                        break;
                                    case 'P':
                                        recN->kind = ikProc;
                                        break;
                                    case 'F':
                                        recN->kind = ikFunc;
                                        recN->type = pInfo->TypeDef;
                                        break;
                                    }

                                    if (pInfo->Args)
                                    {
                                    	BYTE callKind = pInfo->CallKind;
                                        recN->procInfo->flags |= callKind;

                                        ARGINFO argInfo; BYTE *pp = pInfo->Args; int ss = 8;
                                        for (int k = 0; k < pInfo->ArgsNum; k++)
                                        {
                                            FillArgInfo(k, callKind, &argInfo, &pp, &ss);
                                            recN->procInfo->AddArg(&argInfo);
                                        }
                                    }
                                    //Set kbIdx for fast search
                                    recN->kbIdx = Idx;
                                    recN->procInfo->flags |= PF_KBPROTO;
                                }
                            }
                        }
                    }
                }
            }
            continue;
        }
    }
    if (uses) delete[] uses;
}

//---------------------------------------------------------------------------
PMethodRec __fastcall GetMethodInfo(DWORD adr, char kind, int methodOfs)
{
    if (!IsValidCodeAdr(adr)) return 0;

    PInfoRec recN = GetInfoRec(adr);
    if (recN && recN->vmtInfo && recN->vmtInfo->methods)
    {
        for (int n = 0; n < recN->vmtInfo->methods->Count; n++)
        {
            PMethodRec recM = (PMethodRec)recN->vmtInfo->methods->Items[n];
            if (recM->id == methodOfs && recM->kind == kind) return recM;
        }
    }
    return 0;
}
//---------------------------------------------------------------------------
//Return PMethodRec of method with given name
PMethodRec __fastcall GetMethodInfo(PInfoRec rec, String name)
{
    if (rec && rec->vmtInfo->methods)
    {
        for (int m = 0; m < rec->vmtInfo->methods->Count; m++)
        {
            PMethodRec recM = (PMethodRec)rec->vmtInfo->methods->Items[m];
            if (SameText(recM->name, name)) return recM;
        }
    }
    return 0;
}


//---------------------------------------------------------------------------
void __fastcall PropagateVMTNames(DWORD adr)
{
    String  className = GetClsName(adr);
    PInfoRec recN = GetInfoRec(adr);

    DWORD vmtAdr = adr - Vmt.SelfPtr;
    DWORD stopAt = GetStopAt(vmtAdr);
    if (vmtAdr == stopAt) return;

    int pos = Adr2Pos(vmtAdr) + Vmt.Parent + 4;
    for (int m = Vmt.Parent + 4;; m += 4, pos += 4)
    {
        if (Pos2Adr(pos) == stopAt) break;

        DWORD procAdr = *((DWORD*)(Code + pos));
        PInfoRec recN1 = GetInfoRec(procAdr);
        if (!recN1) recN1 = new InfoRec(Adr2Pos(procAdr), ikRefine);

        if (!recN1->HasName())
        {
        	DWORD classAdr = adr;
            while (classAdr)
            {
            	PMethodRec recM = GetMethodInfo(classAdr, 'V', m);
                if (recM)
                {
                    String name = recM->name;
                    if (name != "")
                    {
                        int dotpos = name.Pos(".");
                        if (dotpos)
                            recN1->SetName(className + name.SubString(dotpos, name.Length()));
                        else
                            recN1->SetName(name);

                        PInfoRec recN2 = GetInfoRec(recM->address);
                        recN1->kind = recN2->kind;
                        if (!recN1->procInfo->args && recN2->procInfo->args)
                        {
                        	recN1->procInfo->flags |= recN2->procInfo->flags & 7;
                            //Get Arguments
                            for (int n = 0; n < recN2->procInfo->args->Count; n++)
                            {
                                PARGINFO argInfo2 = (PARGINFO)recN2->procInfo->args->Items[n];
                                ARGINFO argInfo;
                                argInfo.Tag = argInfo2->Tag;
                                argInfo.Register = argInfo2->Register;
                                argInfo.Ndx = argInfo2->Ndx;
                                argInfo.Size = 4;
                                argInfo.Name = argInfo2->Name;
                                argInfo.TypeDef = TrimTypeName(argInfo2->TypeDef);
                                recN1->procInfo->AddArg(&argInfo);
                            }
                        }
                        recN->vmtInfo->AddMethod(false, 'V', m, procAdr, recN1->GetName());
                        break;
                    }
                }
                classAdr = GetParentAdr(classAdr);
            }
        }
    }
}


//---------------------------------------------------------------------------
int __fastcall LoadIntfTable(DWORD adr, TStringList* dstList)
{
    if (!dstList) return 0;
    
    dstList->Clear();
    PInfoRec recN = GetInfoRec(adr);
    if (recN && recN->vmtInfo && recN->vmtInfo->interfaces)
    {
        for (int n = 0; n < recN->vmtInfo->interfaces->Count; n++)
        {
            dstList->Add(recN->vmtInfo->interfaces->Strings[n]);
        }
    }
    dstList->Sort();
    return dstList->Count;
}
//---------------------------------------------------------------------------
int __fastcall LoadAutoTable(DWORD adr, TStringList* dstList)
{
    if (!dstList) return 0;
    
    dstList->Clear();
    PInfoRec recN = GetInfoRec(adr);
    if (recN && recN->vmtInfo && recN->vmtInfo->methods)
    {
        for (int n = 0; n < recN->vmtInfo->methods->Count; n++)
        {
            PMethodRec recM = (PMethodRec)recN->vmtInfo->methods->Items[n];
            if (recM->kind == 'A')
            {
                String line = "A" + Val2Str4(recM->id) + " #" + Val2Str8(recM->address) + " " + recM->name;
                dstList->Add(line);
            }
        }
    }
    dstList->Sort();
    return dstList->Count;
}
//---------------------------------------------------------------------------
int __fastcall LoadFieldTable(DWORD adr, TList* dstList)
{
    if (!dstList) return 0;

    dstList->Clear();
    DWORD parentSize = GetParentSize(adr);
    PInfoRec recN = GetInfoRec(adr);
    if (recN && recN->vmtInfo && recN->vmtInfo->fields)
    {
        for (int n = 0; n < recN->vmtInfo->fields->Count; n++)
        {
            PFIELDINFO fInfo = (PFIELDINFO)recN->vmtInfo->fields->Items[n];
            if (fInfo->Offset >= parentSize)
            {
                bool exist = false;
                for (int m = 0; m < dstList->Count; m++)
                {
                    PFIELDINFO fInfo1 = (PFIELDINFO)dstList->Items[m];
                    if (fInfo1->Offset == fInfo->Offset)
                    {
                        exist = true;
                        break;
                    }
                }
                if (!exist) dstList->Add((void*)fInfo);
            }
        }
    }
    /*
    while (1)
    {
        PInfoRec recN = GetInfoRec(adr);
        if (recN && recN->info && recN->info.vmtInfo->fields)
        {
            for (int n = recN->info.vmtInfo->fields->Count - 1; n >= 0; n--)
            {
                PFIELDINFO fInfo = (PFIELDINFO)recN->info.vmtInfo->fields->Items[n];
                if (!GetVMTField(dstList, fInfo->offset)) dstList->Add((void*)fInfo);
            }
        }
        //ParentAdr
        adr = GetParentAdr(adr);
        if (!adr) break;
    }
    */
    return dstList->Count;
}
//---------------------------------------------------------------------------
int __fastcall LoadMethodTable(DWORD adr, TList* dstList)
{
    if (!dstList) return 0;
    
    dstList->Clear();
    PInfoRec recN = GetInfoRec(adr);
    if (recN && recN->vmtInfo && recN->vmtInfo->methods)
    {
        String className = GetClsName(adr) + ".";
        for (int n = 0; n < recN->vmtInfo->methods->Count; n++)
        {
            PMethodRec recM = (PMethodRec)recN->vmtInfo->methods->Items[n];
            if (recM->kind == 'M')
            {
                if (recM->name.Pos(".") == 0 || recM->name.Pos(className) == 1) dstList->Add((void*)recM);
            }
        }
    }
    return dstList->Count;
}
//---------------------------------------------------------------------------
int __fastcall LoadMethodTable(DWORD adr, TStringList* dstList)
{
    if (!dstList) return 0;
    
    dstList->Clear();
    PInfoRec recN = GetInfoRec(adr);
    if (recN && recN->vmtInfo && recN->vmtInfo->methods)
    {
        for (int n = 0; n < recN->vmtInfo->methods->Count; n++)
        {
            PMethodRec recM = (PMethodRec)recN->vmtInfo->methods->Items[n];
            if (recM->kind == 'M')
            {
                String line = "#" + Val2Str8(recM->address) + " " + recM->name;
                dstList->Add(line);
            }
        }
    }
    return dstList->Count;
}
//---------------------------------------------------------------------------
int __fastcall LoadDynamicTable(DWORD adr, TList* dstList)
{
    if (!dstList) return 0;
    
    dstList->Clear();
    PInfoRec recN = GetInfoRec(adr);
    if (recN && recN->vmtInfo && recN->vmtInfo->methods)
    {
        String className = GetClsName(adr) + ".";
        for (int n = 0; n < recN->vmtInfo->methods->Count; n++)
        {
            PMethodRec recM = (PMethodRec)recN->vmtInfo->methods->Items[n];
            if (recM->kind == 'D')
            {
                if (recM->name.Pos(".") == 0 || recM->name.Pos(className) == 1) dstList->Add((void*)recM);
            }
        }
    }
    return dstList->Count;
}
//---------------------------------------------------------------------------
int __fastcall LoadDynamicTable(DWORD adr, TStringList* dstList)
{
    if (!dstList) return 0;
    
    dstList->Clear();
    PInfoRec recN = GetInfoRec(adr);
    if (recN && recN->vmtInfo && recN->vmtInfo->methods)
    {
        for (int n = 0; n < recN->vmtInfo->methods->Count; n++)
        {
            PMethodRec recM = (PMethodRec)recN->vmtInfo->methods->Items[n];
            if (recM->kind == 'D')
            {
                String line = "D" + Val2Str4(recM->id) + " #" + Val2Str8(recM->address) + " " + recM->name;
                dstList->Add(line);
            }
        }
        dstList->Sort();
    }
    return dstList->Count;
}

//---------------------------------------------------------------------------
static int __fastcall MethodsCmpFunction(void *item1, void *item2)
{
    PMethodRec rec1 = (PMethodRec)item1;
    PMethodRec rec2 = (PMethodRec)item2;

    if (rec1->kind > rec2->kind) return 1;
    if (rec1->kind < rec2->kind) return -1;
    if (rec1->id > rec2->id) return 1;
    if (rec1->id < rec2->id) return -1;
    return 0;
}




//---------------------------------------------------------------------------
int __fastcall LoadVirtualTable(DWORD adr, TList* dstList)
{
    if (!dstList) return 0;
    
    dstList->Clear();
    PInfoRec recN = GetInfoRec(adr);
    if (recN && recN->vmtInfo && recN->vmtInfo->methods)
    {
        String className = GetClsName(adr) + ".";
        recN->vmtInfo->methods->Sort(MethodsCmpFunction);
        for (int n = 0; n < recN->vmtInfo->methods->Count; n++)
        {
            PMethodRec recM = (PMethodRec)recN->vmtInfo->methods->Items[n];
            if (recM->kind == 'V')
            {
                if (recM->name.Pos(".") == 0 || recM->name.Pos(className) == 1) dstList->Add((void*)recM);
            }
        }
    }
    return dstList->Count;
}
//---------------------------------------------------------------------------
int __fastcall LoadVirtualTable(DWORD adr, TStringList* dstList)
{
    if (!dstList) return 0;
    
    dstList->Clear();
    PInfoRec recN = GetInfoRec(adr);
    if (recN && recN->vmtInfo && recN->vmtInfo->methods)
    {
        recN->vmtInfo->methods->Sort(MethodsCmpFunction);
        for (int n = 0; n < recN->vmtInfo->methods->Count; n++)
        {
            PMethodRec recM = (PMethodRec)recN->vmtInfo->methods->Items[n];
            if (recM->kind == 'V')// && recM->id >= -4)
            {
                String line = "";
                PInfoRec recN1 = GetInfoRec(recM->address);

                if (recM->id < 0)
                    line += "-" + Val2Str4(-(recM->id));
                else
                    line += "V" + Val2Str4(recM->id);

                line += " #" + Val2Str8(recM->address);
                if (recM->name != "")
                {
                    line +=  + " " + recM->name;
                    if (recN1 && recN1->HasName() && !recN1->SameName(recM->name))
                    {
                        //Change "@AbstractError" to "abstract"
                        if (SameText(recN1->GetName(), "@AbstractError"))
                            line += " (abstract)";
                        else
                            line += " (" + recN1->GetName() + ")";
                    }
                }
                else
                {
                    if (recN1 && recN1->HasName()) line += " " + recN1->GetName();
                }

                dstList->Add(line);
            }
        }
    }
    return dstList->Count;
}
//---------------------------------------------------------------------------
void __fastcall DelphiVmt::SetVmtConsts(int version)
{
    switch (version)
    {
    case 2012:
    case 2013:
    case 2014:
        SelfPtr           = -0xB0;
        IntfTable         = -0xA8;
        AutoTable         = -0xA0;
        InitTable         = -0x98;
        TypeInfo          = -0x90;
        FieldTable        = -0x88;
        MethodTable       = -0x80;
        DynamicTable      = -0x78;
        ClassName         = -0x70;
        InstanceSize      = -0x68;
        Parent            = -0x60;
        Equals            = -0x58;
        GetHashCode       = -0x50;
        ToString          = -0x48;
        SafeCallException = -0x40;
        AfterConstruction = -0x38;
        BeforeDestruction = -0x30;
        Dispatch          = -0x28;
        DefaultHandler    = -0x20;
        NewInstance       = -0x18;
        FreeInstance      = -0x10;
        Destroy           = -8;
        break;
    }
}
//---------------------------------------------------------------------------
void __fastcall DelphiVmt::AdjustVmtConsts(int Adjustment)
{
    SelfPtr             += Adjustment;
    IntfTable           += Adjustment;
    AutoTable           += Adjustment;
    InitTable           += Adjustment;
    TypeInfo            += Adjustment;
    FieldTable          += Adjustment;
    MethodTable         += Adjustment;
    DynamicTable        += Adjustment;
    ClassName           += Adjustment;
    InstanceSize        += Adjustment;
    Parent              += Adjustment;
    Equals              += Adjustment;
    GetHashCode         += Adjustment;
    ToString            += Adjustment;
    SafeCallException   += Adjustment;
    AfterConstruction   += Adjustment;
    BeforeDestruction   += Adjustment;
    Dispatch            += Adjustment;
    DefaultHandler      += Adjustment;
    NewInstance         += Adjustment;
    FreeInstance        += Adjustment;
    Destroy             += Adjustment;
}
//---------------------------------------------------------------------------
Idr64Manager::Idr64Manager()
{
    IDR64Version = "12.04.2017";
    _ResInfo = new TResourceInfo;
};
Idr64Manager::~Idr64Manager()
{
    //todo Phoenix singleton patter?  (idr object is destroyed earlier comparing to forms!)
    //delete _ResInfo;;
};

PInfoRec Idr64Manager::GetInfos(DWORD classAdr)
{
    PInfoRec        recN;
    recN = (IsValidImageAdr(classAdr)) ? Infos[Adr2Pos(classAdr)] : 0;
    return recN;
}
PInfoRec Idr64Manager::GetInfosAt(int Pos)
{
    assert(Pos >= 0); //? && < maxsize
    return Infos[Pos];
}

bool Idr64Manager::HasInfosAt(int Pos)
{
    return (Infos[Pos] != 0);
}
void Idr64Manager::SetInfosAt(int Pos, PInfoRec rec)
{
    if (HasInfosAt(Pos))
    {
        //as: if we here - memory leak then!
        ++stat_InfosOverride;
    }

    Infos[Pos] = rec;
}

void Idr64Manager::CreateDBs(DWORD _TotalSize)
{
    Flags = new DWORD[_TotalSize];
    memset(Flags, cfUndef, sizeof(DWORD) * _TotalSize);

    Infos = new PInfoRec[_TotalSize];
    memset(Infos, 0, sizeof(PInfoRec) * _TotalSize);

    BSSInfos = new TStringList;
    BSSInfos->Sorted = true;
}
