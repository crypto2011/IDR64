//---------------------------------------------------------------------
#include <vcl.h>
#pragma hdrstop

#include "AboutDlg.h"
#include "Misc.h"

//---------------------------------------------------------------------
#pragma package(smart_init)
#pragma resource "*.dfm"

//extern	String	IDR64Version;

TFAboutDlg_11011981 *FAboutDlg_11011981;
//---------------------------------------------------------------------
__fastcall TFAboutDlg_11011981::TFAboutDlg_11011981(TComponent* AOwner)
	: TForm(AOwner)
{
}
//---------------------------------------------------------------------
void __fastcall TFAboutDlg_11011981::FormCreate(TObject *Sender)
{
	lVer->Caption = "Version: " + idr.GetVersion();
    ScaleForm(this);
}
//---------------------------------------------------------------------------
void __fastcall TFAboutDlg_11011981::lEmailClick(TObject *Sender)
{
	ShellExecute(Handle, "open", "mailto:crypto2011@gmail.com", 0, 0, 1);
}
//---------------------------------------------------------------------------
void __fastcall TFAboutDlg_11011981::lWWWClick(TObject *Sender)
{
	ShellExecute(Handle, "open", "http://kpnc.org/idr32/en/", 0, 0, 1);
}
//---------------------------------------------------------------------------
void __fastcall TFAboutDlg_11011981::bDonateClick(TObject *Sender)
{
	ShellExecute(Handle, "open", "http://kpnc.org/idr32/en/donation.htm", 0, 0, 1);
}
//---------------------------------------------------------------------------

