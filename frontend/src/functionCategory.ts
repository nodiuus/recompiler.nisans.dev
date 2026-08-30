import type { AnalyzedFunction } from "./types";

// Heuristic only: the PDB doesn't flag which symbols are user code vs.
// compiler/library generated, so this classifies functions by well-known
// MSVC naming conventions, mangling patterns, and the object files the
// static CRT always pulls in.

export type FunctionCategory = "user" | "crt" | "msvc" | "stl";

export const FUNCTION_CATEGORIES: FunctionCategory[] = ["user", "crt", "msvc", "stl"];

export const CATEGORY_LABELS: Record<FunctionCategory, string> = {
  user: "User",
  crt: "CRT",
  msvc: "MSVC internals",
  stl: "STL",
};

const CRT_MODULE_MARKERS = [/^import:/i, /^\*\s*linker\s*\*$/i];

const CRT_OBJECT_NAMES = new Set(
  [
    "gs_support.obj",
    "gs_cookie.obj",
    "chkstk.obj",
    "loadcfg.obj",
    "utility.obj",
    "utility_desktop.obj",
    "argv_mode.obj",
    "cfguard_support.obj",
    "default_local_stdio_options.obj",
    "dyn_tls_init.obj",
    "dyn_tls_dtor.obj",
    "tncleanup.obj",
    "initializers.obj",
    "initsect.obj",
    "initos.obj",
    "ucrt_detection.obj",
    "commit_mode.obj",
    "app_type.obj",
    "invalid_parameter_handler.obj",
    "matherr_detection.obj",
    "onexit.obj",
    "exe_main.obj",
    "exe_winmain.obj",
    "dll_dllmain.obj",
    "std_type_info_static.obj",
    "typinfo.obj",
    "pesect.obj",
    "stdio_options.obj",
    "cpu_disp.obj",
    "tlssup.obj",
    "crt0.obj",
    "crt0dat.obj",
    "crtexe.obj",
  ].map((n) => n.toLowerCase()),
);

const CRT_NAME_EXACT = new Set([
  "mainCRTStartup",
  "wmainCRTStartup",
  "WinMainCRTStartup",
  "wWinMainCRTStartup",
  "_DllMainCRTStartup",
  "DllMainCRTStartup",
  "_onexit",
  "atexit",
  "_cexit",
  "_c_exit",
  "_amsg_exit",
  "_purecall",
  "_invalid_parameter",
  "_invalid_parameter_noinfo",
  "_invalid_parameter_noinfo_noreturn",
  "_matherr",
  "_chkstk",
  "__chkstk",
  "_alloca_probe",
  "_alloca_probe_16",
  "_security_check_cookie",
]);

const CRT_NAME_PREFIXES = [
  "__scrt_",
  "__security_",
  "__report_",
  "__raise_",
  "__vcrt_",
  "__acrt_",
  "__std_",
  "__isa_available",
  "__dyn_tls_",
  "_RTC_",
  "_guard_",
  "__guard_",
  "_except_handler",
  "__CxxFrameHandler",
  "__GSHandlerCheck",
  "__GSHandlerCheck_SEH",
  "_initterm",
  "_get_startup_",
  "__crt",
  "_stdio_common_",
  "__local_stdio_",
  "operator new",
  "operator delete",
];

// std:: (and the pre-Dinkumware stdext:: extension namespace) anywhere in a
// qualified name is a strong signal the symbol came from the STL headers
// rather than application code.
const STL_NAME_PATTERN = /\bstd(ext)?::/;

// Compiler-synthesized helpers: vtables/vbtables/vcall thunks, RTTI locators,
// special member thunks, and the various "`...'" scaffolding names MSVC
// mints for statics, exception unwinding, and defaulted special members.
const MSVC_BACKTICK_PATTERN = /`/;
const MSVC_DECORATED_PATTERN = /^\?\?_[0-9A-Z]/;

function decoratedOrPublicName(fn: AnalyzedFunction): string {
  return fn.decoratedName ?? (fn.visibility === "public" ? fn.name : "");
}

function decoratedNameIsOwnedByStl(name: string): boolean {
  if (!name.startsWith("?")) return false;

  // In an MSVC symbol such as ?fn@Solution@@..., the first @@ closes the
  // function's qualified owner. Any @std@@ after that belongs to the return
  // or parameter types and must not turn the user-owned function into STL.
  const stlOwner = name.search(/@std(?:ext)?@@/i);
  if (stlOwner < 0) return false;
  const qualifiedNameEnd = name.indexOf("@@");
  return qualifiedNameEnd < 0 || stlOwner <= qualifiedNameEnd;
}

function isStlFunction(fn: AnalyzedFunction): boolean {
  if (STL_NAME_PATTERN.test(fn.name)) return true;

  // Procedure records normally provide the readable owner (for example,
  // Solution::brightestPosition). Its public counterpart can still contain
  // @std@@ solely because the signature accepts std::vector, std::string,
  // etc. Only fall back to mangled-name inspection when the displayed name
  // itself is an undecoded MSVC symbol.
  return decoratedNameIsOwnedByStl(fn.name);
}

function isMsvcInternal(fn: AnalyzedFunction): boolean {
  if (MSVC_BACKTICK_PATTERN.test(fn.name)) return true;
  if (fn.name === "type_info" || fn.name.startsWith("type_info::")) return true;
  if (fn.name.includes("RTTI")) return true;
  return MSVC_DECORATED_PATTERN.test(decoratedOrPublicName(fn));
}

function isCrtFunction(fn: AnalyzedFunction): boolean {
  const module = (fn.module ?? "").trim();
  if (module && CRT_MODULE_MARKERS.some((re) => re.test(module))) return true;
  if (module && CRT_OBJECT_NAMES.has(module.toLowerCase())) return true;
  if (CRT_NAME_EXACT.has(fn.name)) return true;
  return CRT_NAME_PREFIXES.some((prefix) => fn.name.startsWith(prefix));
}

export function classifyFunction(fn: AnalyzedFunction): FunctionCategory {
  if (isStlFunction(fn)) return "stl";
  if (isMsvcInternal(fn)) return "msvc";
  if (isCrtFunction(fn)) return "crt";
  return "user";
}
