"""Port of Group3r/Options/AssessmentOptions/FileExtensions.cs

The C# bodies are `AssessmentOptions.LoadExeAndScriptExtensions()`,
`LoadConfigFileExtensions()` and `LoadOfficeMacroExtensions()` on the partial
class; here they are module-level loaders that the corresponding
`AssessmentOptions` methods call. Order is preserved.
"""


def load_exe_and_script_extensions() -> list[str]:
    return [
        "exe",
        "msi",
        "bat",
        "cmd",
        "hta",
        "ps1",
        "vbs",
        "scr",
        "com",
        "psd1",
        "psm1",
        "lnk",
    ]  # yeah i know it's not technically but it works like these so it's going here.


def load_config_file_extensions() -> list[str]:
    return [
        "config",
        "xml",
        "json",
        "ini",
        "rdp",
        "conf",
        "cnf",
    ]


def load_office_macro_extensions() -> list[str]:
    return [
        "dot",
        "dotm",
        "doc",
        "docm",
        "xlt",
        "xls",
        "xltm",
        "xlsm",
        "pot",
        "potm",
        "ppt",
        "pptm",
    ]
