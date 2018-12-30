//---------------------------------------------------------------------
#include <vcl.h>
#pragma hdrstop

#include "InputDlg.h"
#include "Misc.h"
//--------------------------------------------------------------------- 
#pragma package(smart_init)
#pragma resource "*.dfm"

TFInputDlg_11011981 *FInputDlg_11011981;
//---------------------------------------------------------------------
__fastcall TFInputDlg_11011981::TFInputDlg_11011981(TComponent* AOwner)
	: TForm(AOwner)
{
}
//---------------------------------------------------------------------
void __fastcall TFInputDlg_11011981::FormShow(TObject *Sender)
{
    if (edtName->CanFocus()) ActiveControl = edtName;
}
//---------------------------------------------------------------------------
void __fastcall TFInputDlg_11011981::edtNameEnter(TObject *Sender)
{
 	edtName->SelectAll();
}
//---------------------------------------------------------------------------
void __fastcall TFInputDlg_11011981::FormCreate(TObject *Sender)
{
    ScaleForm(this);
}
//---------------------------------------------------------------------------
String __fastcall InputDialogExec(String caption, String labelText, String text)
{
    String _result = "";

    FInputDlg_11011981->Caption = caption;
    FInputDlg_11011981->edtName->EditLabel->Caption = labelText;
    FInputDlg_11011981->edtName->Text = text;
    while (_result == "")
    {
        if (FInputDlg_11011981->ShowModal() == mrCancel) break;
        _result = FInputDlg_11011981->edtName->Text.Trim();
    }
    return _result;
}
//---------------------------------------------------------------------------
