import argparse
import PySimpleGUI as sg
import itertools
import os
import pathlib
import ctypes


parser = argparse.ArgumentParser(description="Given an SRUM database it will create an XLS spreadsheet with analysis of the data in the database.")
parser.add_argument("--SRUM_INFILE","-i", help ="Specify the ESE (.dat) file to analyze. Provide a valid path to the file.")
parser.add_argument("--XLSX_OUTFILE", "-o", default="SRUM_DUMP_OUTPUT.xlsx", help="Full path to the XLS file that will be created.")
parser.add_argument("--XLSX_TEMPLATE" ,"-t", help = "The Excel Template that specifies what data to extract from the srum database. You can create template_tables with ese_template.py.")
parser.add_argument("--REG_HIVE", "-r", dest="reghive", help = "If a registry hive is provided then the names of the network profiles will be resolved.")
parser.add_argument("--quiet", "-q", help = "Supress unneeded output messages.",action="store_true")
options = parser.parse_args()

ads = itertools.cycle(["Did you know SANS Automating Infosec with Python SEC573 teaches you to develop Forensics and Incident Response tools?",
       "To learn how SRUM and other artifacts can enhance your forensics investigations check out SANS Windows Forensic Analysis FOR500.",
       "Yogesh Khatri's paper at https://files.sans.org/summit/Digital_Forensics_and_Incident_Response_Summit_2015/PDFs/Windows8SRUMForensicsYogeshKhatri.pdf was essential in the creation of this tool.",
       "By modifying the template file you have control of what ends up in the analyzed results.  Try creating an alternate template and passing it with the --XLSX_TEMPLATE option.",
       "TIP: When using a SOFTWARE registry file you can add your own SIDS to the 'lookup-Known SIDS' tab!",
       "This program was written by Twitter:@markbaggett and @donaldjwilliam5 because @ovie said so.",
       "SRUM-DUMP 2.0 will attempt to dump any ESE database! If not template defines a table it will do its best to guess."
       ])

if not options.SRUM_INFILE:
    srum_path = ""
    if os.path.exists("SRUDB.DAT"):
        srum_path = os.path.join(os.getcwd(),"SRUDB.DAT")
    temp_path = pathlib.Path.cwd() / "SRUM_TEMPLATE2.XLSX"
    if temp_path.exists():
        temp_path = str(temp_path)
    else:
        temp_path = ""
    reg_path = ""
    if os.path.exists("SOFTWARE"):
        reg_path = os.path.join(os.getcwd(),"SOFTWARE")

    layout = [[sg.Text('Optoinal: Path to System Events c:\windows\system32\Winevt\Logs\System.evtx')],
    [sg.Input(srum_path,key="_SYSTEMEVENTS_", enable_events=True), sg.FileBrowse(target="_SYSTEMEVENTS_")], 
    [sg.Text('Optional: SOFTWARE registry file c:\windows\system32\config\SYSTEM*')],
    [sg.Input(temp_path,key="_SOFTWARE_"), sg.FileBrowse(target="_SOFTWARE_")],
    [sg.Text('Optional: WLAN Logs c:\windows\system32\Winevt\Logs\Microsoft-Windows-WLAN-AutoConfig perational.evtx')],
    [sg.Input(key="_WLANLOGS_"), sg.FileBrowse(target="_WLANLOGS_")],
    [sg.Text('REQUIRED: Configuration file with API keys')],
    [sg.Input(os.getcwd(),key='_APIKEYS_'), sg.FolderBrowse(target='_APIKEYS_')],
    [sg.Text('REQUIRED: Output folder for results.')],
    [sg.Input(os.getcwd(),key='_OUTDIR_'), sg.FolderBrowse(target='_OUTDIR_')],
    [sg.Text("Click here for support via Twitter @MarkBaggett",enable_events=True, key="_SUPPORT_", text_color="Blue")],
    [sg.OK(), sg.Cancel()]] 

    if ctypes.windll.shell32.IsUserAnAdmin() == 1:
        layout[-1].append(sg.Button("Auto Extract"))
    
    # Create the Window
    window = sg.Window('werejugo 0.1', layout)
    while True:             
        event, values = window.Read()
        if event is None:
            break
        if event == "_SUPPORT_":
            webbrowser.open("https://twitter.com/MarkBaggett")
        if event == 'Cancel':
            sys.exit(0)
        if event == "Auto Extract":
            return_value = extract_live_file()

        if event == "_SRUMPATH_":
            if str(pathlib.Path(values.get("_SRUMPATH_"))).lower() == "c:\\windows\\system32\\sru\\srudb.dat":
                result = show_live_system_warning() 
                if result:
                    window.Element("_SRUMPATH_").Update(result[0])
                    window.Element("_REGPATH_").Update(result[1])
                continue
        if event == 'OK':
            tmp_path = pathlib.Path(values.get("_SRUMPATH_"))
            if not tmp_path.exists() or not tmp_path.is_file():
                sg.PopupOK("SRUM DATABASE NOT FOUND.")
                continue
            if not os.path.exists(pathlib.Path(values.get("_OUTDIR_"))):
                sg.PopupOK("OUTPUT DIR NOT FOUND.")
                continue
            tmp_path = pathlib.Path(values.get("_TEMPATH_"))            
            if not tmp_path.exists() or not tmp_path.is_file():
                sg.PopupOK("SRUM TEMPLATE NOT FOUND.")
                continue
            tmp_path = pathlib.Path(values.get("_REGPATH_"))
            if values.get("_REGPATH_") and not tmp_path.exists() and not tmp_path.is_file():
                sg.PopupOK("REGISTRY File not found. (Leave field empty for None.)")
                continue
            break

    window.Close()
    options.SRUM_INFILE = str(pathlib.Path(values.get("_SRUMPATH_")))
    options.XLSX_OUTFILE = str(pathlib.Path(values.get("_OUTDIR_")) / "SRUM_DUMP_OUTPUT.xlsx")
    options.XLSX_TEMPLATE = str(pathlib.Path(values.get("_TEMPATH_")))
    options.reghive = str(pathlib.Path(values.get("_REGPATH_")))
    if options.reghive == ".":
        options.reghive = ""