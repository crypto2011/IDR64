//---------------------------------------------------------------------------
#ifndef MainH
#define MainH
//---------------------------------------------------------------------------
#include <stdio.h>
#include <Classes.hpp>
#include <Controls.hpp>
#include <StdCtrls.hpp>
#include <Forms.hpp>
#include <Menus.hpp>
#include <Dialogs.hpp>
#include <ComCtrls.hpp>
#include <Grids.hpp>
#include <ExtCtrls.hpp>
#include <Buttons.hpp>
#include <ActnList.hpp>
#include "Disasm.h"
#include "KnowledgeBase.h"
#include "Resources.h"
#include "Infos.h"
#include "Misc.h"
#include "UFileDropper.h"
#include <AppEvnts.hpp>

//---------------------------------------------------------------------------
#define USER_KNOWLEDGEBASE      0x80000000
#define SOURCE_LIBRARY          0x40000000
#define DELHPI_VERSION_AUTO     0
//---------------------------------------------------------------------------
//Internal unit types
#define drStop              0
#define drStop_a            0x61    //'a' - Last Tag in all files
#define drStop1             0x63    //'c'
#define drUnit              0x64    //'d'
#define drUnit1             0x65    //'e' - in implementation
#define drImpType           0x66    //'f'
#define drImpVal            0x67    //'g'
#define drDLL               0x68    //'h'
#define drExport            0x69    //'i'
#define drEmbeddedProcStart 0x6A    //'j'
#define drEmbeddedProcEnd   0x6B    //'k'
#define drCBlock            0x6C    //'l'
#define drFixUp             0x6D    //'m'
#define drImpTypeDef        0x6E    //'n' - import of type definition by "A = type B"
#define drUnit2             0x6F    //'o' - ??? for D2010
#define drSrc               0x70    //'p'
#define drObj               0x71    //'q'
#define drRes               0x72    //'r'
#define drAsm               0x73    //'s' - Found in D5 Debug versions
#define drStop2             0x9F    //'_'
#define drConst             0x25    //'%'
#define drResStr            0x32    //'2'
#define drType              0x2A    //'*'
#define drTypeP             0x26    //'&'
#define drProc              0x28    //'('
#define drSysProc           0x29    //')'
#define drVoid              0x40    //'@'
#define drVar               0x20    //' '
#define drThreadVar         0x31    //'1'
#define drVarC              0x27    //'''
#define drBoolRangeDef      0x41    //'A'
#define drChRangeDef        0x42    //'B'
#define drEnumDef           0x43    //'C'
#define drRangeDef          0x44    //'D'
#define drPtrDef            0x45    //'E'
#define drClassDef          0x46    //'F'
#define drObjVMTDef         0x47    //'G'
#define drProcTypeDef       0x48    //'H'
#define drFloatDef          0x49    //'I'
#define drSetDef            0x4A    //'J'
#define drShortStrDef       0x4B    //'K'
#define drArrayDef          0x4C    //'L'
#define drRecDef            0x4D    //'M'
#define drObjDef            0x4E    //'N'
#define drFileDef           0x4F    //'O'
#define drTextDef           0x50    //'P'
#define drWCharRangeDef     0x51    //'Q' - WideChar
#define drStringDef         0x52    //'R'
#define drVariantDef        0x53    //'S'
#define drInterfaceDef      0x54    //'T'
#define drWideStrDef        0x55    //'U'
#define drWideRangeDef      0x56    //'V'
//---------------------------------------------------------------------------
int __fastcall MethodsCmpFunction(void *item1, void *item2);
int __fastcall ArgsCmpFunction(void *item1, void *item2);
int __fastcall ExportsCmpFunction(void *item1, void *item2);
int __fastcall ImportsCmpFunction(void *item1, void *item2);

enum NameVersion {nvPrimary, nvAfterScan, nvByUser};
//XRef Type
#define XREF_UNKNOWN    0x20    //Black
#define XREF_CALL       1       //Blue
#define XREF_JUMP       2       //Green
#define XREF_CONST      3       //Light red

typedef struct
{
    String      name;
    DWORD       address;
    WORD        ord;
} ExportNameRec, *PExportNameRec;

typedef struct
{
    String      module;
    String      name;
    DWORD       address;
} ImportNameRec, *PImportNameRec;

//Proc navigation history record
typedef struct
{
    DWORD       adr;            //Procedure Address
    int         itemIdx;        //Selected Item Index
    int         xrefIdx;        //Selected Xref Index
    int         topIdx;         //TopIndex of ListBox
} PROCHISTORYREC, *PPROCHISTORYREC;
//---------------------------------------------------------------------------
//Common
#define		MAXLEN		        100
#define     MAXLINE             1024
#define     MAXNAME             1024
#define     IDPMAGICLEN         18
#define     IDPMAGIC            "IDR64 project file"
#define     IDPVERSION          1
#define     MAXBINTEMPLATE      1000
#define     MAX_ITEMS           0x10000    //Max items number for read-write
#define     HISTORY_CHUNK_LENGTH    256
//Search
#define     SEARCH_UNITS        0
#define     SEARCH_UNITITEMS    1
#define     SEARCH_RTTIS        2
#define     SEARCH_CLASSVIEWER  3
#define		SEARCH_STRINGS		4
#define		SEARCH_FORMS        5
#define     SEARCH_CODEVIEWER   6
#define     SEARCH_NAMES        7
#define     SEARCH_SOURCEVIEWER 8
//---------------------------------------------------------------------------

class TDfm;
class TAnalyzeThread;

class TFMain_11011981 : public TForm
{
__published:	// IDE-managed Components
    TMenuItem *miFile;
    TMenuItem *miLoadFile;
    TMenuItem *miExit;
    TMenuItem *miSaveProject;
    TOpenDialog *OpenDlg;
    TMainMenu *MainMenu;
    TMenuItem *miTools;
    TPageControl *pcInfo;
    TTabSheet *tsUnits;
    TTabSheet *tsRTTIs;
    TListBox *lbUnits;
    TListBox *lbRTTIs;
    TMenuItem *miOpenProject;
    TPageControl *pcWorkArea;
	TTabSheet *tsCodeView;
    TListBox *lbCode;
    TPopupMenu *pmCode;
    TMenuItem *miGoTo;
    TMenuItem *miExploreAdr;
    TSaveDialog *SaveDlg;
    TSplitter *SplitterH1;
    TSplitter *SplitterV1;
    TMenuItem *miViewProto;
    TPanel *CodePanel;
    TButton *bEP;
    TButton *bCodePrev;
	TTabSheet *tsClassView;
    TTreeView *tvClassesFull;
    TTabSheet *tsStrings;
    TListBox *lbStrings;
    TPanel *Panel1;
    TPopupMenu *pmUnits;
    TMenuItem *miSearchUnit;
    TMenuItem *miSortUnits;
    TMenuItem *miSortUnitsByAdr;
    TMenuItem *miSortUnitsByOrd;
    TPopupMenu *pmRTTIs;
    TPopupMenu *pmVMTs;
    TMenuItem *miSearchRTTI;
    TMenuItem *miSortRTTI;
    TMenuItem *miSortRTTIsByAdr;
    TMenuItem *miSortRTTIsByKnd;
    TMenuItem *miSortRTTIsByNam;
    TMenuItem *miSearchVMT;
    TMenuItem *miCopyCode;
    TMenuItem *miRenameUnit;
    TPopupMenu *pmUnitItems;
    TMenuItem *miSearchItem;
    TTabSheet *tsForms;
    TPanel *Panel2;
    TRadioGroup *rgViewFormAs;
    TListBox *lbForms;
    TMenuItem *miCollapseAll;
	TListBox *lbCXrefs;
	TPanel *ShowCXrefs;
    TMenuItem *miSortUnitsByNam;
    TTreeView *tvClassesShort;
    TRadioGroup *rgViewerMode;
    TMenuItem *miClassTreeBuilder;
    TMenuItem *miMRF;
    TMenuItem *miExe1;
    TMenuItem *miExe2;
    TMenuItem *miExe3;
    TMenuItem *miExe4;
    TMenuItem *miIdp1;
    TMenuItem *miIdp2;
    TMenuItem *miIdp3;
    TMenuItem *miIdp4;
    TMenuItem *N1;
    TTabSheet *tsItems;
    TStringGrid *sgItems;
    TMenuItem *miExe5;
    TMenuItem *miExe6;
    TMenuItem *miExe7;
    TMenuItem *miExe8;
    TMenuItem *miIdp5;
    TMenuItem *miIdp6;
    TMenuItem *miIdp7;
    TMenuItem *miIdp8;
    TListBox *lbUnitItems;
	TMenuItem *miEditFunctionC;
    TMenuItem *miMapGenerator;
    TMenuItem *miAutodetectVersion;
    TMenuItem *miKBTypeInfo;
	TMenuItem *miName;
	TMenuItem *miLister;
	TButton *bCodeNext;
	TLabel *lProcName;
    TMenuItem *miInformation;
	TMenuItem *miEditFunctionI;
	TPopupMenu *pmStrings;
	TMenuItem *miSearchString;
	TMenuItem *miViewClass;
	TPanel *Panel3;
	TListBox *lbSXrefs;
	TPanel *ShowSXrefs;
	TMenuItem *miAbout;
	TMenuItem *miHelp;
	TMenuItem *miEditClass;
	TMenuItem *miCtdPassword;
	TPopupMenu *pmCodePanel;
	TMenuItem *miEmptyHistory;
    TMenuItem *miTabs;
    TMenuItem *Units1;
    TMenuItem *RTTI1;
    TMenuItem *Forms1;
    TMenuItem *CodeViewer1;
    TMenuItem *ClassViewer1;
    TMenuItem *Strings1;
    TMenuItem *miUnitDumper;
    TTabSheet *tsNames;
    TMenuItem *Names1;
    TListBox *lbNames;
    TPanel *Panel4;
    TSplitter *Splitter1;
    TListBox *lbAliases;
    TPanel *pnlAliases;
    TLabel *lClassName;
    TComboBox *cbAliases;
    TButton *bApplyAlias;
    TButton *bCancelAlias;
    TMenuItem *miLegend;
    TMenuItem *miFuzzyScanKB;
    TMenuItem *miCopyList;
    TMenuItem *miCommentsGenerator;
    TMenuItem *miIDCGenerator;
    TMenuItem *miSaveDelphiProject;
    TTabSheet *tsSourceCode;
    TListBox *lbSourceCode;
    TMenuItem *SourceCode1;
    TPanel *Panel5;
    TPanel *ShowNXrefs;
    TListBox *lbNXrefs;
    TMenuItem *miHex2Double;
    TActionList *alMain;
    TAction *acOnTop;
    TAction *acShowBar;
    TAction *acShowHoriz;
    TAction *acDefCol;
    TAction *acColorThis;
    TAction *acFontAll;
    TAction *acColorAll;
    TFontDialog *FontsDlg;
    TMenuItem *Appearance2;
    TMenuItem *Colorsall2;
    TMenuItem *Colorsthis2;
    TMenuItem *Fontall2;
    TMenuItem *Fontthis2;
    TMenuItem *Defaultcolumns2;
    TMenuItem *Showhorizontalscroll2;
    TMenuItem *Showbar2;
    TButton *bDecompile;
    TMenuItem *miCopyStrings;
    TMenuItem *miCopyAddressI;
    TMenuItem *miCopyAddressCode;
    TPopupMenu *pmSourceCode;
    TMenuItem *miCopySource2Clipboard;
    TMenuItem *miXRefs;
    TMenuItem *miDelphiXE2;
    TMenuItem *miPlugins;
    TMenuItem *miViewAll;
    TCheckBox *cbMultipleSelection;
    TMenuItem *miSwitchSkipFlag;
    TMenuItem *miSwitchFrameFlag;
    TMenuItem *miSwitchFlag;
    TMenuItem *miDelphiXE3;
    TMenuItem *miSettings;
    TMenuItem *miacFontAll;
    TMenuItem *miDelphiXE4;
    TMenuItem *miProcessDumper;
    TApplicationEvents *AppEvents;
    void __fastcall miExitClick(TObject *Sender);
    void __fastcall miAutodetectVersionClick(TObject *Sender);
    void __fastcall FormCreate(TObject *Sender);
    void __fastcall FormDestroy(TObject *Sender);
    void __fastcall miSaveProjectClick(TObject *Sender);
    void __fastcall miOpenProjectClick(TObject *Sender);
    void __fastcall lbCodeDblClick(TObject *Sender);
    void __fastcall bEPClick(TObject *Sender);
    void __fastcall lbStringsDblClick(TObject *Sender);
    void __fastcall lbRTTIsDblClick(TObject *Sender);
    void __fastcall lbUnitItemsDblClick(TObject *Sender);
    void __fastcall lbUnitsDblClick(TObject *Sender);
    void __fastcall miGoToClick(TObject *Sender);
	void __fastcall miExploreAdrClick(TObject *Sender);
    void __fastcall miNameClick(TObject *Sender);
    void __fastcall miViewProtoClick(TObject *Sender);
    void __fastcall lbXrefsDblClick(TObject *Sender);
    void __fastcall bCodePrevClick(TObject *Sender);
    void __fastcall tvClassesDblClick(TObject *Sender);
    void __fastcall miSearchUnitClick(TObject *Sender);
    void __fastcall miSortUnitsByAdrClick(TObject *Sender);
    void __fastcall miSortUnitsByOrdClick(TObject *Sender);
    void __fastcall miSearchVMTClick(TObject *Sender);
    void __fastcall miSearchRTTIClick(TObject *Sender);
    void __fastcall miSortRTTIsByAdrClick(TObject *Sender);
    void __fastcall miSortRTTIsByKndClick(TObject *Sender);
    void __fastcall miSortRTTIsByNamClick(TObject *Sender);
    void __fastcall miCopyCodeClick(TObject *Sender);
    void __fastcall miRenameUnitClick(TObject *Sender);
    void __fastcall FormClose(TObject *Sender, TCloseAction &Action);
    void __fastcall lbFormsDblClick(TObject *Sender);
    void __fastcall lbUnitsDrawItem(TWinControl *Control,
          int Index, TRect &Rect, TOwnerDrawState State);
    void __fastcall FormKeyDown(TObject *Sender, WORD &Key,
          TShiftState Shift);
    void __fastcall lbCodeKeyDown(TObject *Sender, WORD &Key,
          TShiftState Shift);
    void __fastcall miCollapseAllClick(TObject *Sender);
    void __fastcall NamePosition();
    void __fastcall GoToAddress();
    void __fastcall FindText(String Str);
    void __fastcall miSearchItemClick(TObject *Sender);
    void __fastcall ShowCXrefsClick(TObject *Sender);
    void __fastcall lbUnitItemsDrawItem(TWinControl *Control,
          int Index, TRect &Rect, TOwnerDrawState State);
    void __fastcall lbUnitsMouseMove(TObject *Sender,
          TShiftState Shift, int X, int Y);
    void __fastcall lbRTTIsMouseMove(TObject *Sender,
          TShiftState Shift, int X, int Y);
    void __fastcall lbFormsMouseMove(TObject *Sender,
          TShiftState Shift, int X, int Y);
    void __fastcall lbCodeMouseMove(TObject *Sender,
          TShiftState Shift, int X, int Y);
    void __fastcall tvClassesFullMouseMove(TObject *Sender,
          TShiftState Shift, int X, int Y);
    void __fastcall lbStringsMouseMove(TObject *Sender,
          TShiftState Shift, int X, int Y);
    void __fastcall lbUnitItemsMouseMove(TObject *Sender,
          TShiftState Shift, int X, int Y);
    void __fastcall lbXrefsMouseMove(TObject *Sender,
          TShiftState Shift, int X, int Y);
    void __fastcall miSortUnitsByNamClick(TObject *Sender);
    void __fastcall rgViewerModeClick(TObject *Sender);
    void __fastcall tvClassesShortMouseMove(TObject *Sender,
          TShiftState Shift, int X, int Y);
    void __fastcall miClassTreeBuilderClick(TObject *Sender);
    void __fastcall lbUnitsClick(TObject *Sender);
    void __fastcall lbRTTIsClick(TObject *Sender);
    void __fastcall lbUnitItemsClick(TObject *Sender);
    void __fastcall tvClassesShortClick(TObject *Sender);
    void __fastcall tvClassesFullClick(TObject *Sender);
    void __fastcall miExe1Click(TObject *Sender);
    void __fastcall miExe2Click(TObject *Sender);
    void __fastcall miExe3Click(TObject *Sender);
    void __fastcall miExe4Click(TObject *Sender);
    void __fastcall miIdp1Click(TObject *Sender);
    void __fastcall miIdp2Click(TObject *Sender);
    void __fastcall miIdp3Click(TObject *Sender);
    void __fastcall miIdp4Click(TObject *Sender);
    void __fastcall FormShow(TObject *Sender);    
    void __fastcall miKBTypeInfoClick(TObject *Sender);
    void __fastcall miExe5Click(TObject *Sender);
    void __fastcall miExe6Click(TObject *Sender);
    void __fastcall miExe7Click(TObject *Sender);
    void __fastcall miExe8Click(TObject *Sender);
    void __fastcall miIdp5Click(TObject *Sender);
    void __fastcall miIdp6Click(TObject *Sender);
    void __fastcall miIdp7Click(TObject *Sender);
    void __fastcall miIdp8Click(TObject *Sender);
    void __fastcall FormResize(TObject *Sender);
    void __fastcall miEditFunctionCClick(TObject *Sender);
    void __fastcall lbXrefsDrawItem(TWinControl *Control, int Index,
          TRect &Rect, TOwnerDrawState State);
    void __fastcall miMapGeneratorClick(TObject *Sender);
    void __fastcall pmUnitsPopup(TObject *Sender);
    void __fastcall lbCodeDrawItem(TWinControl *Control, int Index,
          TRect &Rect, TOwnerDrawState State);
    void __fastcall lbXrefsKeyDown(TObject *Sender, WORD &Key,
          TShiftState Shift);
    void __fastcall lbUnitsKeyDown(TObject *Sender, WORD &Key,
          TShiftState Shift);
    void __fastcall lbRTTIsKeyDown(TObject *Sender, WORD &Key,
          TShiftState Shift);
    void __fastcall lbFormsKeyDown(TObject *Sender, WORD &Key,
          TShiftState Shift);
    void __fastcall tvClassesShortKeyDown(TObject *Sender, WORD &Key,
          TShiftState Shift);
    void __fastcall lbUnitItemsKeyDown(TObject *Sender, WORD &Key,
          TShiftState Shift);
    void __fastcall miListerClick(TObject *Sender);
	void __fastcall bCodeNextClick(TObject *Sender);
	void __fastcall miEditFunctionIClick(TObject *Sender);
	void __fastcall miSearchStringClick(TObject *Sender);
	void __fastcall lbStringsClick(TObject *Sender);
	void __fastcall miViewClassClick(TObject *Sender);
	void __fastcall pmVMTsPopup(TObject *Sender);
	void __fastcall lbStringsDrawItem(TWinControl *Control, int Index,
          TRect &Rect, TOwnerDrawState State);
	void __fastcall ShowSXrefsClick(TObject *Sender);
	void __fastcall miAboutClick(TObject *Sender);
	void __fastcall miHelpClick(TObject *Sender);
	void __fastcall pmRTTIsPopup(TObject *Sender);
	void __fastcall FormCloseQuery(TObject *Sender, bool &CanClose);
	void __fastcall miEditClassClick(TObject *Sender);
	void __fastcall miCtdPasswordClick(TObject *Sender);
	void __fastcall pmCodePanelPopup(TObject *Sender);
	void __fastcall miEmptyHistoryClick(TObject *Sender);
    void __fastcall pmStringsPopup(TObject *Sender);
    void __fastcall Units1Click(TObject *Sender);
    void __fastcall RTTI1Click(TObject *Sender);
    void __fastcall Forms1Click(TObject *Sender);
    void __fastcall CodeViewer1Click(TObject *Sender);
    void __fastcall ClassViewer1Click(TObject *Sender);
    void __fastcall Strings1Click(TObject *Sender);
    void __fastcall Names1Click(TObject *Sender);
    void __fastcall miUnitDumperClick(TObject *Sender);
    void __fastcall miFuzzyScanKBClick(TObject *Sender);
    void __fastcall lbNamesClick(TObject *Sender);
    void __fastcall bApplyAliasClick(TObject *Sender);
    void __fastcall bCancelAliasClick(TObject *Sender);
    void __fastcall lbAliasesDblClick(TObject *Sender);
    void __fastcall miLegendClick(TObject *Sender);
    void __fastcall miCopyListClick(TObject *Sender);
    void __fastcall miCommentsGeneratorClick(TObject *Sender);
    void __fastcall miIDCGeneratorClick(TObject *Sender);
    void __fastcall miSaveDelphiProjectClick(TObject *Sender);
    void __fastcall bDecompileClick(TObject *Sender);
    void __fastcall SourceCode1Click(TObject *Sender);
    void __fastcall miHex2DoubleClick(TObject *Sender);
    void __fastcall acFontAllExecute(TObject *Sender);
    void __fastcall pmUnitItemsPopup(TObject *Sender);
    void __fastcall miCopyAddressIClick(TObject *Sender);
    void __fastcall miCopyAddressCodeClick(TObject *Sender);
    void __fastcall miCopySource2ClipboardClick(TObject *Sender);
    void __fastcall pmCodePopup(TObject *Sender);
    void __fastcall lbFormsClick(TObject *Sender);
    void __fastcall lbCodeClick(TObject *Sender);
    void __fastcall pcInfoChange(TObject *Sender);
    void __fastcall pcWorkAreaChange(TObject *Sender);
    void __fastcall miDelphiXE2Click(TObject *Sender);
    void __fastcall miPluginsClick(TObject *Sender);
    void __fastcall miCopyStringsClick(TObject *Sender);
    void __fastcall miViewAllClick(TObject *Sender);
    void __fastcall lbSourceCodeMouseMove(TObject *Sender,
          TShiftState Shift, int X, int Y);
    void __fastcall cbMultipleSelectionClick(TObject *Sender);
    void __fastcall lbSourceCodeDrawItem(TWinControl *Control, int Index,
          TRect &Rect, TOwnerDrawState State);
    void __fastcall miSwitchSkipFlagClick(TObject *Sender);
    void __fastcall miSwitchFrameFlagClick(TObject *Sender);
    void __fastcall miDelphiXE3Click(TObject *Sender);
    void __fastcall miDelphiXE4Click(TObject *Sender);
    void __fastcall miProcessDumperClick(TObject *Sender);
    void __fastcall AppEventsRestore(TObject *Sender);
private:	// User declarations
    bool            ProjectLoaded;
    TAnalyzeThread  *AnalyzeThread; //Поток для фонового анализа кода
    int             AnalyzeThreadRetVal;

    void __fastcall Init();
    void __fastcall AnalyzeThreadDone(TObject* Sender);

    bool __fastcall IsExe(String FileName);
    bool __fastcall IsIdp(String FileName);
    void __fastcall LoadFile(String FileName, int version);
    void __fastcall LoadDelphiFile(int version);
    void __fastcall LoadDelphiFile1(String FileName, int version, bool loadExp, bool loadImp);
    void __fastcall ReadNode(TStream* stream, TTreeNode* node, char* buf);
    void __fastcall OpenProject(String FileName);
    bool __fastcall ImportsValid(DWORD ImpRVA, DWORD ImpSize);
    int __fastcall LoadImage(String imageFile, bool loadExp, bool loadImp);
    void __fastcall FindExports();
    void __fastcall FindImports();
    int __fastcall GetDelphiVersion();
    void __fastcall InitSysProcs();
    int __fastcall GetUnits(String dprName);
    int __fastcall GetBCBUnits(String dprName);
    
    void __fastcall CodeHistoryPush(PPROCHISTORYREC rec);
    PPROCHISTORYREC __fastcall CodeHistoryPop();
    
    void __fastcall ShowCodeXrefs(ULONGLONG Adr, int selIdx);
    void __fastcall ShowStringXrefs(ULONGLONG Adr, int selIdx);
    void __fastcall ShowNameXrefs(ULONGLONG Adr, int selIdx);

    void __fastcall WriteNode(TStream* stream, TTreeNode* node);
    void __fastcall SaveProject(String FileName);
    void __fastcall CloseProject();
    void __fastcall CleanProject();
    void __fastcall IniFileRead();
    void __fastcall IniFileWrite();
    void __fastcall AddExe2MRF(String FileName);
    void __fastcall AddIdp2MRF(String FileName);

    int __fastcall CodeGetTargetAdr(String line, DWORD* trgAdr);
    void __fastcall OutputLine(FILE* outF, BYTE flags, DWORD adr, String content);
	void __fastcall OutputCode(FILE* outF, DWORD fromAdr, String prototype, bool onlyComments);

    //Drag&Drop
    TDragDropHelper dragdropHelper;
    void __fastcall wm_dropFiles(TWMDropFiles& msg);
    void __fastcall DoOpenProjectFile(String FileName);
    bool __fastcall ContainsUnexplored(PUnitRec recU);

    //GUI update from thread
    void __fastcall wm_updAnalysisStatus(TMessage& msg);
    void __fastcall wm_dfmOpen(TMessage& msg);
    void __fastcall wm_dfmClosed(TMessage& msg);
    void __fastcall wm_showCode(TMessage& msg);
    void __fastcall wm_showClassViewer(TMessage& msg);

    //void __fastcall wm_WMSysCommand(TWMSysCommand& msg);
    
    //Tree view booster
    typedef std::map<const String, TTreeNode*> TTreeNodeNameMap;
    TTreeNodeNameMap tvClassMap;
    void __fastcall ClearTreeNodeMap();

    void __fastcall SetupAllFonts(TFont* font);
    void __fastcall ParseCommandLineArgs();
    String __fastcall GetFilenameFromLink(String LinkName);
    void __fastcall LogMessage(const AnsiString& msg, const int flags);

    void __fastcall miSearchFormClick(TObject *Sender);
    void __fastcall miSearchNameClick(TObject *Sender);

public:		// User declarations
    bool        quietMode;
    String      AppDir;
    String      WrkDir;
    //String      SourceFile;
    int         SysProcsNum;

    int         WhereSearch;
    //UNITS
    int         UnitsSearchFrom;
    TStringList *UnitsSearchList;
    String      UnitsSearchText;
    //RTTIS
    int         RTTIsSearchFrom;
    TStringList *RTTIsSearchList;
    String      RTTIsSearchText;
    //UNITITEMS
    int         UnitItemsSearchFrom;
    TStringList *UnitItemsSearchList;
    String      UnitItemsSearchText;
    //FORMS
    int         FormsSearchFrom;
    TStringList *FormsSearchList;    
    String      FormsSearchText;
    //VMTS
    TTreeNode	*TreeSearchFrom;
    TTreeNode	*BranchSearchFrom;
    TStringList *VMTsSearchList;
    String      VMTsSearchText;
    //STRINGS
    int			StringsSearchFrom;
    TStringList	*StringsSearchList;
    String		StringsSearchText;
    //NAMES
    int			NamesSearchFrom;
    TStringList	*NamesSearchList;
    String		NamesSearchText;

    //code navigation vars
    int         CodeHistorySize;    //Current size of Code navigation History Array
    int         CodeHistoryPtr;     //Curent pointer of Code navigation History Array
    int		    CodeHistoryMax;		//Max pointer position of Code navigation History Array (for ->)
    DynamicArray<PROCHISTORYREC> CodeHistory;   //Code navigation History Array

    bool        SourceIsLibrary;
    bool        ClassTreeDone;
    bool        ProjectModified;
    bool        UserKnowledgeBase;

    int         RTTISortField; //0 - by address, 1 - by initialization order, 2 - by name

    __fastcall TFMain_11011981(TComponent* Owner);
    __fastcall ~TFMain_11011981();
    
    void __fastcall DoOpenDelphiFile(int version, String FileName, bool loadExp, bool loadImp);
    DWORD __fastcall FollowInstructions(DWORD fromAdr, DWORD toAdr);
    ULONGLONG __fastcall EvaluateInitTable(BYTE* Data, DWORD Size, ULONGLONG Base);
    int __fastcall GetMethodOfs(PInfoRec rec, DWORD procAdr);

    PImportNameRec __fastcall GetImportRec(DWORD adr);
    void __fastcall ShowUnits(bool showUnk);
    void __fastcall ShowUnitItems(PUnitRec recU, int topIdx, int itemIdx);
    void __fastcall ShowRTTIs();
    void __fastcall FillVmtList();
    void __fastcall ShowClassViewer(DWORD VmtAdr);

    TTreeNode* __fastcall GetNodeByName(String AName);

    void __fastcall ShowStrings(int idx);
    void __fastcall ShowNames(int idx);
    void __fastcall RedrawCode();
    int __fastcall AddAsmLine(DWORD Adr, String text, BYTE Flags);
    void __fastcall ShowCode(ULONGLONG fromAdr, int SelectedIdx, int XrefIdx, int topIdx);

    void __fastcall FillClassViewer();
    void __fastcall FillClassViewerOne(int n, TStringList* tmpList, const bool* terminated);
    TTreeNode* __fastcall AddClassTreeNode(TTreeNode* node, String name);
    //Function
    void __fastcall EditFunction(DWORD Adr);

    void __fastcall InitAliases(bool find);
    void __fastcall CopyAddress(String line, int ofs, int bytes);
    void __fastcall GoToXRef(TObject *Sender);
    void __fastcall OutputDecompilerHeader(FILE* f);

    BEGIN_MESSAGE_MAP
    VCL_MESSAGE_HANDLER(WM_DROPFILES, TWMDropFiles, wm_dropFiles);
    VCL_MESSAGE_HANDLER(WM_UPDANALYSISSTATUS, TMessage, wm_updAnalysisStatus);
    VCL_MESSAGE_HANDLER(WM_DFMOPEN, TMessage, wm_dfmOpen);
    VCL_MESSAGE_HANDLER(WM_DFMCLOSED, TMessage, wm_dfmClosed);
    VCL_MESSAGE_HANDLER(WM_SHOWCODE, TMessage, wm_showCode);
    VCL_MESSAGE_HANDLER(WM_SHOWCLASSVIEWER, TMessage, wm_showClassViewer);
    //VCL_MESSAGE_HANDLER(WM_SYSCOMMAND, TWMSysCommand, wm_WMSysCommand);
    END_MESSAGE_MAP(TForm)

    //Treenode booster for analysis
    void __fastcall AddTreeNodeWithName(TTreeNode* node, const String& name);
    TTreeNode* __fastcall FindTreeNodeByName(const String& name);

    //show Form by its dfm object
    void __fastcall ShowDfm(TDfm* dfm);
};
//---------------------------------------------------------------------------
extern PACKAGE TFMain_11011981 *FMain_11011981;
//---------------------------------------------------------------------------
#endif
