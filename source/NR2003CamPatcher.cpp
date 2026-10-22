// NR2003 Cockpit Camera Patcher
// Sets the cockpit view FOV and cockpit camera offset directly into NR2003.exe.
// Standalone Win32 GUI. Build with MSVC x86 (/MT).
//
// Cockpit FOV (file offset = VA - 0x400000):
//   The cockpit view ignores the "field_of_view" profile option and is rendered
//   with the aspect-correction base FOV stored as a double at VA 0x6F69A0
//   (file 0x2F69A0), radian units, stock value 1.13438045 (~65 deg at 4:3).
//   The renderer applies a Hor+ correction:  screen = 2*atan(0.75*tan(base/2)*aspect)
//   so the patcher inverts that (16:9) to make the typed value the on-screen FOV.
//   Only this constant is changed; every other camera is restored to stock.
//
// Cockpit offset (file offsets):
//   X VA 0x74EBBC  file 0x34EBBC  (float)
//   Y VA 0x74EBC0  file 0x34EBC0  (float)
//   Z VA 0x74EBC4  file 0x34EBC4  (float)
//
// Stock values restored by the FOV patch so nothing else changes:
//   FOV slider min/max/default  VA 0x6F5F00 / 0x6F5F04 / 0x6EF48C  (65 / 78 / 65)
//   profile FOV getter operand  VA 0x441C12  (-> 0x00894EE8)
//   profile FOV setter          VA 0x441C20  (original code)
//   camera-array (.cam) FOV blk VA 0x56AFA0  (original 42 bytes)
//   renderer FOV load           VA 0x587E70  (original code)

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <commdlg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#define IDC_EDIT_PATH   1001
#define IDC_BTN_BROWSE  1002
#define IDC_EDIT_FOV    1003
#define IDC_EDIT_OX     1004
#define IDC_EDIT_OY     1005
#define IDC_EDIT_OZ     1006
#define IDC_BTN_APPLY   1007
#define IDC_BTN_REVERT  1008
#define IDC_STATUS      1009
#define IDC_CHK_FOV     1010
#define IDC_CHK_OFFSET  1011

static const long OFF_FOV_MIN_CONST = 0x2F5F00; // float, degrees
static const long OFF_FOV_MAX_CONST = 0x2F5F04; // float, degrees
static const long OFF_FOV_DEF_CONST = 0x2EF48C; // float, degrees
static const long OFF_GETTER_OPERAND = 0x41C12; // dword
static const long OFF_SETTER = 0x41C20;         // code
static const long OFF_ASPECT_FOV_BASE = 0x2F69A0; // double, radians (aspect-correction base FOV)
static const long OFF_RENDER_FOV_LOAD = 0x187E70; // code: fld [esi+0x121] -> fld [0x6f69a0]
static const long OFF_OFFSET_X = 0x34EBBC;
static const long OFF_OFFSET_Y = 0x34EBC0;
static const long OFF_OFFSET_Z = 0x34EBC4;

static const DWORD ADDR_FOV_VAR = 0x00894EE8;    // original getter operand (profile FOV variable)
static const DWORD ADDR_FOV_CONST = 0x006EF48C;  // const the getter will read

// Profile FOV setter, VA 0x441C20:
//   original: mov eax,[esp+4]; mov [0x894EE8],eax; ret   (10 bytes + nop)
//   patched : mov dword [0x894EE8],<FOV>;   ret          (11 bytes)
// Forcing the variable here guarantees the cockpit always sees our FOV even after
// a profile load has tried to overwrite it with the saved value.
static const unsigned char SETTER_ORIG[11] = {
    0x8B,0x44,0x24,0x04,        // mov  eax,[esp+4]
    0xA3,0xE8,0x4E,0x89,0x00,   // mov  [0x894EE8],eax
    0xC3,                       // ret
    0x90                        // nop (next byte, untouched tail)
};
static const unsigned char SETTER_PATCH_HEAD[6] = {
    0xC7,0x05,0xE8,0x4E,0x89,0x00  // mov dword [0x894EE8], imm32
};

// DIAGNOSTIC: force the renderer's base FOV load (VA 0x587E70) to read the shared
// aspect-base constant instead of the per-view camera FOV. Used to determine
// whether the cockpit view goes through this render path at all.
static const unsigned char RENDER_FOV_LOAD_ORIG[6] = { 0xD9,0x86,0x21,0x01,0x00,0x00 }; // fld [esi+0x121]
static const unsigned char RENDER_FOV_LOAD_PATCH[6] = { 0xD9,0x05,0xA0,0x69,0x6F,0x00 }; // fld [0x6f69a0]

// Camera-array (.cam) FOV path: the block at VA 0x56AFA0 (func B case 4, views
// 10-15) copies the FOV from the .cam element triplet {fov,0,-0.125} at +0x18
// into render-camera +0x98. We replace that copy so the FOV always reads the
// shared constant at 0x6EF48C, leaving the rest of the block's behaviour intact.
static const long OFF_ARRAY_FOV_BLOCK = 0x16AFA0; // file offset
static const unsigned char ARRAY_FOV_ORIG[42] = {
    0x8D,0xB5,0x98,0x00,0x00,0x00, // lea  esi,[ebp+0x98]
    0x83,0xC3,0x18,               // add  ebx,0x18
    0x8B,0xCE,                    // mov  ecx,esi
    0x8B,0x13,                    // mov  edx,[ebx]
    0x89,0x11,                    // mov  [ecx],edx
    0x8B,0x43,0x04,               // mov  eax,[ebx+4]
    0x89,0x41,0x04,               // mov  [ecx+4],eax
    0x8B,0x53,0x08,               // mov  edx,[ebx+8]
    0xC7,0x85,0xA4,0x00,0x00,0x00,0xCD,0xCC,0x4C,0x3E, // mov [ebp+0xa4],0.2
    0x89,0x51,0x08,               // mov  [ecx+8],edx
    0xE9,0xB6,0x03,0x00,0x00      // jmp  0x56B380
};
static const unsigned char ARRAY_FOV_PATCHED[42] = {
    0x8D,0xB5,0x98,0x00,0x00,0x00, // lea  esi,[ebp+0x98]
    0xA1,0x8C,0xF4,0x6E,0x00,      // mov  eax,[0x6EF48C]  (fixed FOV const)
    0x89,0x06,                    // mov  [esi],eax
    0xC7,0x46,0x04,0x00,0x00,0x00,0x00, // mov dword [esi+4],0
    0xC7,0x46,0x08,0x00,0x00,0x00,0xBE, // mov dword [esi+8],0xBE000000 (-0.125)
    0xC7,0x85,0xA4,0x00,0x00,0x00,0xCD,0xCC,0x4C,0x3E, // mov [ebp+0xa4],0.2
    0xE9,0xB6,0x03,0x00,0x00      // jmp  0x56B380
};

static HWND g_hPath, g_hFov, g_hOx, g_hOy, g_hOz, g_hStatus, g_hChkFov, g_hChkOffset;

static void SetStatus(const char *fmt, ...) {
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    _vsnprintf(buf, sizeof(buf) - 1, fmt, ap);
    buf[sizeof(buf) - 1] = 0;
    va_end(ap);
    SetWindowTextA(g_hStatus, buf);
}

static BOOL ReadAt(FILE *f, long off, void *dst, size_t n) {
    if (fseek(f, off, SEEK_SET) != 0) return FALSE;
    return fread(dst, 1, n, f) == n;
}
static BOOL WriteAt(FILE *f, long off, const void *src, size_t n) {
    if (fseek(f, off, SEEK_SET) != 0) return FALSE;
    return fwrite(src, 1, n, f) == n;
}

static void GetText(HWND h, char *buf, int n) {
    GetWindowTextA(h, buf, n);
}

static BOOL ParseFloat(HWND h, float *out) {
    char buf[64];
    GetText(h, buf, sizeof(buf));
    char *end = NULL;
    float v = (float)strtod(buf, &end);
    if (end == buf) return FALSE;
    *out = v;
    return TRUE;
}

static void LoadCurrent(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) return;
    float v;
    char buf[64];
    {
        double base;
        if (ReadAt(f, OFF_ASPECT_FOV_BASE, &base, 8)) {
            const double PI = 3.14159265358979323846;
            const double aspect = 16.0 / 9.0;
            double screen = 2.0 * atan(0.75 * tan(base * 0.5) * aspect);
            sprintf(buf, "%.4g", screen * 180.0 / PI);
            SetWindowTextA(g_hFov, buf);
        }
    }
    if (ReadAt(f, OFF_OFFSET_X, &v, 4)) { sprintf(buf, "%.4g", v); SetWindowTextA(g_hOx, buf); }
    if (ReadAt(f, OFF_OFFSET_Y, &v, 4)) { sprintf(buf, "%.4g", v); SetWindowTextA(g_hOy, buf); }
    if (ReadAt(f, OFF_OFFSET_Z, &v, 4)) { sprintf(buf, "%.4g", v); SetWindowTextA(g_hOz, buf); }
    fclose(f);
}

static void MakeBackup(const char *path, BOOL *made) {
    *made = FALSE;
    char bak[MAX_PATH];
    _snprintf(bak, sizeof(bak), "%s.bak", path);
    bak[sizeof(bak) - 1] = 0;
    if (GetFileAttributesA(bak) == INVALID_FILE_ATTRIBUTES) {
        if (CopyFileA(path, bak, TRUE)) *made = TRUE;
    }
}

static void OnBrowse(HWND hwnd) {
    char path[MAX_PATH] = {0};
    GetText(g_hPath, path, sizeof(path));
    OPENFILENAMEA ofn;
    ZeroMemory(&ofn, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hwnd;
    ofn.lpstrFilter = "NR2003 (NR2003.exe)\0NR2003.exe\0Executables (*.exe)\0*.exe\0All files (*.*)\0*.*\0";
    ofn.lpstrFile = path;
    ofn.nMaxFile = sizeof(path);
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_HIDEREADONLY;
    if (GetOpenFileNameA(&ofn)) {
        SetWindowTextA(g_hPath, path);
        LoadCurrent(path);
        SetStatus("Loaded current values from exe.");
    }
}

static void OnApply(HWND hwnd) {
    char path[MAX_PATH];
    GetText(g_hPath, path, sizeof(path));
    if (path[0] == 0) { SetStatus("ERROR: choose NR2003.exe first."); return; }

    BOOL doFov = (SendMessageA(g_hChkFov, BM_GETCHECK, 0, 0) == BST_CHECKED);
    BOOL doOff = (SendMessageA(g_hChkOffset, BM_GETCHECK, 0, 0) == BST_CHECKED);
    if (!doFov && !doOff) { SetStatus("Nothing selected - tick FOV and/or offset."); return; }

    float fov = 0.0f, ox = 0.0f, oy = 0.0f, oz = 0.0f;
    if (doFov) {
        if (!ParseFloat(g_hFov, &fov)) { SetStatus("ERROR: invalid FOV value."); return; }
        if (fov < 1.0f || fov > 170.0f) { SetStatus("ERROR: FOV must be between 1 and 170."); return; }
    }
    if (doOff) {
        if (!ParseFloat(g_hOx, &ox) || !ParseFloat(g_hOy, &oy) || !ParseFloat(g_hOz, &oz)) {
            SetStatus("ERROR: invalid offset value."); return;
        }
    }

    FILE *f = fopen(path, "r+b");
    if (!f) { SetStatus("ERROR: cannot open '%s' (is the game running?)", path); return; }

    // sanity: file must be large enough
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    if (sz < 0x34EBC8) { fclose(f); SetStatus("ERROR: file too small - not the expected NR2003.exe."); return; }

    // sanity: getter should be 'fld [0x894EE8]' unless already patched to our const
    if (doFov) {
        unsigned char gb[7];
        if (!ReadAt(f, OFF_GETTER_OPERAND - 2, gb, 7)) { fclose(f); SetStatus("ERROR: read failed."); return; }
        if (gb[0] != 0xD9 || gb[1] != 0x05) {
            fclose(f); SetStatus("ERROR: FOV getter signature mismatch (unsupported exe build)."); return;
        }
        DWORD curOperand;
        memcpy(&curOperand, gb + 2, 4);
        if (curOperand != ADDR_FOV_VAR && curOperand != ADDR_FOV_CONST) {
            fclose(f);
            SetStatus("ERROR: unexpected getter operand 0x%08X (unsupported exe build).", curOperand);
            return;
        }

        // sanity: camera-array FOV block must be original or already patched
        unsigned char ab[42];
        if (!ReadAt(f, OFF_ARRAY_FOV_BLOCK, ab, 42)) {
            fclose(f); SetStatus("ERROR: read failed (camera-array block)."); return;
        }
        if (memcmp(ab, ARRAY_FOV_ORIG, 42) != 0 && memcmp(ab, ARRAY_FOV_PATCHED, 42) != 0) {
            fclose(f);
            SetStatus("ERROR: camera-array FOV block mismatch (unsupported exe build).");
            return;
        }

        // sanity: profile FOV setter must be original or already patched
        unsigned char sb[11];
        if (!ReadAt(f, OFF_SETTER, sb, 11)) {
            fclose(f); SetStatus("ERROR: read failed (FOV setter)."); return;
        }
        if (memcmp(sb, SETTER_ORIG, 11) != 0 &&
            !(sb[0] == 0xC7 && sb[1] == 0x05 && sb[10] == 0xC3)) {
            fclose(f);
            SetStatus("ERROR: FOV setter signature mismatch (unsupported exe build).");
            return;
        }
    }

    BOOL madeBak = FALSE;
    MakeBackup(path, &madeBak);

    BOOL ok = TRUE;
    if (doFov) {
        // The cockpit view ignores the "field_of_view" profile option and instead
        // uses the renderer's aspect-correction base FOV (a double at VA 0x6F69A0).
        // The renderer computes the on-screen FOV as a Hor+ correction of that base:
        //     screen = 2*atan( 0.75 * tan(base/2) * aspect )
        // Invert it for 16:9 so the number typed is the actual on-screen cockpit FOV.
        const double PI = 3.14159265358979323846;
        const double aspect = 16.0 / 9.0;
        double half = (double)fov * PI / 360.0;                 // fov/2, in radians
        double baseRad = 2.0 * atan( tan(half) / (0.75 * aspect) );
        ok &= WriteAt(f, OFF_ASPECT_FOV_BASE, &baseRad, 8);

        // Leave every other camera at stock so ONLY the cockpit changes: undo any
        // earlier overrides (array cameras, profile FOV option, renderer load).
        ok &= WriteAt(f, OFF_ARRAY_FOV_BLOCK, ARRAY_FOV_ORIG, 42);
        DWORD stockOperand = ADDR_FOV_VAR;
        ok &= WriteAt(f, OFF_GETTER_OPERAND, &stockOperand, 4);
        ok &= WriteAt(f, OFF_SETTER, SETTER_ORIG, 11);
        float sMin = 65.0f, sMax = 78.0f, sDef = 78.0f;
        ok &= WriteAt(f, OFF_FOV_MIN_CONST, &sMin, 4);
        ok &= WriteAt(f, OFF_FOV_MAX_CONST, &sMax, 4);
        ok &= WriteAt(f, OFF_FOV_DEF_CONST, &sDef, 4);
        ok &= WriteAt(f, OFF_RENDER_FOV_LOAD, RENDER_FOV_LOAD_ORIG, 6);
        // set profile FOV to max (78°) so mirror looks good; cockpit ignores this
        //float pfov = 78.0f;
        //ok &= WriteAt(f, (long)(ADDR_FOV_VAR - 0x400000), &pfov, 4);
    }
    if (doOff) {
        ok &= WriteAt(f, OFF_OFFSET_X, &ox, 4);
        ok &= WriteAt(f, OFF_OFFSET_Y, &oy, 4);
        ok &= WriteAt(f, OFF_OFFSET_Z, &oz, 4);
    }

    if (fflush(f) != 0) ok = FALSE;
    fclose(f);

    if (!ok) { SetStatus("ERROR: failed while writing patches."); return; }

    if (doFov && doOff)
        SetStatus("Applied FOV=%.4g deg + offset=(%.4g, %.4g, %.4g).%s",
                  fov, ox, oy, oz, madeBak ? " Backup created (.bak)." : "");
    else if (doFov)
        SetStatus("Applied FOV=%.4g deg only (offset untouched).%s",
                  fov, madeBak ? " Backup created (.bak)." : "");
    else
        SetStatus("Applied offset=(%.4g, %.4g, %.4g) only (FOV untouched).%s",
                  ox, oy, oz, madeBak ? " Backup created (.bak)." : "");
}

static void OnRevert(HWND hwnd) {
    char path[MAX_PATH];
    GetText(g_hPath, path, sizeof(path));
    if (path[0] == 0) { SetStatus("ERROR: choose NR2003.exe first."); return; }
    char bak[MAX_PATH];
    _snprintf(bak, sizeof(bak), "%s.bak", path);
    bak[sizeof(bak) - 1] = 0;
    if (GetFileAttributesA(bak) == INVALID_FILE_ATTRIBUTES) {
        SetStatus("No backup found (%s.bak).", path);
        return;
    }
    if (!CopyFileA(bak, path, FALSE)) {
        SetStatus("ERROR: could not restore backup (is the game running?).");
        return;
    }
    LoadCurrent(path);
    SetStatus("Reverted from backup.");
}

static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_CREATE: {
        HINSTANCE hi = ((LPCREATESTRUCT)lp)->hInstance;
        HFONT font = (HFONT)GetStockObject(DEFAULT_GUI_FONT);
        int y = 12;

        CreateWindowExA(0, "STATIC", "NR2003.exe path:", WS_CHILD | WS_VISIBLE, 12, y + 3, 100, 18, hwnd, NULL, hi, NULL);
        g_hPath = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "", WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL,
                                  115, y, 230, 22, hwnd, (HMENU)IDC_EDIT_PATH, hi, NULL);
        CreateWindowExA(0, "BUTTON", "Browse...", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
                        352, y, 80, 22, hwnd, (HMENU)IDC_BTN_BROWSE, hi, NULL);
        y += 38;

        CreateWindowExA(0, "STATIC", "Fixed FOV (degrees):", WS_CHILD | WS_VISIBLE, 12, y + 3, 140, 18, hwnd, NULL, hi, NULL);
        g_hFov = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "80", WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL,
                                 155, y, 70, 22, hwnd, (HMENU)IDC_EDIT_FOV, hi, NULL);
        y += 38;

        CreateWindowExA(0, "STATIC", "Cockpit camera offset (x, y, z):", WS_CHILD | WS_VISIBLE, 12, y, 220, 18, hwnd, NULL, hi, NULL);
        y += 22;
        CreateWindowExA(0, "STATIC", "x", WS_CHILD | WS_VISIBLE, 12, y + 3, 12, 18, hwnd, NULL, hi, NULL);
        g_hOx = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "0.1", WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL,
                                28, y, 80, 22, hwnd, (HMENU)IDC_EDIT_OX, hi, NULL);
        CreateWindowExA(0, "STATIC", "y", WS_CHILD | WS_VISIBLE, 120, y + 3, 12, 18, hwnd, NULL, hi, NULL);
        g_hOy = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "0.0", WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL,
                                136, y, 80, 22, hwnd, (HMENU)IDC_EDIT_OY, hi, NULL);
        CreateWindowExA(0, "STATIC", "z", WS_CHILD | WS_VISIBLE, 228, y + 3, 12, 18, hwnd, NULL, hi, NULL);
        g_hOz = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "0.1", WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL,
                                244, y, 80, 22, hwnd, (HMENU)IDC_EDIT_OZ, hi, NULL);
        y += 34;

        CreateWindowExA(0, "STATIC",
                        "Offset is in car-local space; axis meaning (forward/up/right) may need testing.\n"
                        "A .bak backup is created on first apply.",
                        WS_CHILD | WS_VISIBLE, 12, y, 420, 32, hwnd, NULL, hi, NULL);
        y += 40;

        g_hChkFov = CreateWindowExA(0, "BUTTON", "Apply FOV override", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTOCHECKBOX,
                                    12, y, 170, 20, hwnd, (HMENU)IDC_CHK_FOV, hi, NULL);
        g_hChkOffset = CreateWindowExA(0, "BUTTON", "Apply camera offset", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTOCHECKBOX,
                                       200, y, 170, 20, hwnd, (HMENU)IDC_CHK_OFFSET, hi, NULL);
        SendMessageA(g_hChkFov, BM_SETCHECK, BST_CHECKED, 0);
        SendMessageA(g_hChkOffset, BM_SETCHECK, BST_CHECKED, 0);
        y += 28;

        CreateWindowExA(0, "BUTTON", "Apply to NR2003.exe", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON,
                        12, y, 170, 30, hwnd, (HMENU)IDC_BTN_APPLY, hi, NULL);
        CreateWindowExA(0, "BUTTON", "Revert (restore .bak)", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
                        192, y, 170, 30, hwnd, (HMENU)IDC_BTN_REVERT, hi, NULL);
        y += 40;

        g_hStatus = CreateWindowExA(0, "STATIC", "Ready.", WS_CHILD | WS_VISIBLE | SS_LEFT,
                                    12, y, 424, 40, hwnd, (HMENU)IDC_STATUS, hi, NULL);

        EnumChildWindows(hwnd, [](HWND c, LPARAM p) -> BOOL {
            SendMessageA(c, WM_SETFONT, (WPARAM)GetStockObject(DEFAULT_GUI_FONT), TRUE);
            return TRUE;
        }, 0);

        // auto-detect exe next to the patcher
        char self[MAX_PATH] = {0};
        GetModuleFileNameA(NULL, self, sizeof(self));
        char *slash = strrchr(self, '\\');
        if (slash) {
            *(slash + 1) = 0;
            char cand[MAX_PATH];
            _snprintf(cand, sizeof(cand), "%sNR2003.exe", self);
            if (GetFileAttributesA(cand) != INVALID_FILE_ATTRIBUTES) {
                SetWindowTextA(g_hPath, cand);
                LoadCurrent(cand);
            }
        }
        SetFocus(g_hPath);
        return 0;
    }
    case WM_COMMAND: {
        switch (LOWORD(wp)) {
        case IDC_BTN_BROWSE: OnBrowse(hwnd); return 0;
        case IDC_BTN_APPLY:  OnApply(hwnd);  return 0;
        case IDC_BTN_REVERT: OnRevert(hwnd); return 0;
        }
        return 0;
    }
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcA(hwnd, msg, wp, lp);
}

int WINAPI WinMain(HINSTANCE hi, HINSTANCE hp, LPSTR cmd, int show) {
    (void)hp; (void)cmd;
    WNDCLASSA wc;
    ZeroMemory(&wc, sizeof(wc));
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hi;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.lpszClassName = "NR2003CamPatcherWnd";
    RegisterClassA(&wc);

    HWND hwnd = CreateWindowExA(0, wc.lpszClassName, "NR2003 Cam Patcher",
                                WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
                                CW_USEDEFAULT, CW_USEDEFAULT, 460, 400,
                                NULL, NULL, hi, NULL);
    if (!hwnd) return 1;
    ShowWindow(hwnd, show);
    UpdateWindow(hwnd);

    MSG msg;
    while (GetMessageA(&msg, NULL, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageA(&msg);
    }
    return (int)msg.wParam;
}
