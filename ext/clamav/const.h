    /* return codes */

    /* libclamav specific */
    rb_define_const(cClamAV, "CL_CLEAN", INT2FIX(CL_CLEAN));
    rb_define_const(cClamAV, "CL_SUCCESS", INT2FIX(CL_SUCCESS));
    rb_define_const(cClamAV, "CL_VIRUS", INT2FIX(CL_VIRUS));
    rb_define_const(cClamAV, "CL_ENULLARG", INT2FIX(CL_ENULLARG));
    rb_define_const(cClamAV, "CL_EARG", INT2FIX(CL_EARG));
    rb_define_const(cClamAV, "CL_EMALFDB", INT2FIX(CL_EMALFDB));
    rb_define_const(cClamAV, "CL_ECVD", INT2FIX(CL_ECVD));
    rb_define_const(cClamAV, "CL_EVERIFY", INT2FIX(CL_EVERIFY));
    rb_define_const(cClamAV, "CL_EUNPACK", INT2FIX(CL_EUNPACK));

    /* I/O and memory errors */
    rb_define_const(cClamAV, "CL_EOPEN", INT2FIX(CL_EOPEN));
    rb_define_const(cClamAV, "CL_ECREAT", INT2FIX(CL_ECREAT));
    rb_define_const(cClamAV, "CL_EUNLINK", INT2FIX(CL_EUNLINK));
    rb_define_const(cClamAV, "CL_ESTAT", INT2FIX(CL_ESTAT));
    rb_define_const(cClamAV, "CL_EREAD", INT2FIX(CL_EREAD));
    rb_define_const(cClamAV, "CL_ESEEK", INT2FIX(CL_ESEEK));
    rb_define_const(cClamAV, "CL_EWRITE", INT2FIX(CL_EWRITE));
    rb_define_const(cClamAV, "CL_EDUP", INT2FIX(CL_EDUP));
    rb_define_const(cClamAV, "CL_EACCES", INT2FIX(CL_EACCES));
    rb_define_const(cClamAV, "CL_ETMPFILE", INT2FIX(CL_ETMPFILE));
    rb_define_const(cClamAV, "CL_ETMPDIR", INT2FIX(CL_ETMPDIR));
    rb_define_const(cClamAV, "CL_EMAP", INT2FIX(CL_EMAP));
    rb_define_const(cClamAV, "CL_EMEM", INT2FIX(CL_EMEM));
    rb_define_const(cClamAV, "CL_ETIMEOUT", INT2FIX(CL_ETIMEOUT));

    /* internal (not reported outside libclamav) */
    rb_define_const(cClamAV, "CL_BREAK", INT2FIX(CL_BREAK));
    rb_define_const(cClamAV, "CL_EMAXREC", INT2FIX(CL_EMAXREC));
    rb_define_const(cClamAV, "CL_EMAXSIZE", INT2FIX(CL_EMAXSIZE));
    rb_define_const(cClamAV, "CL_EMAXFILES", INT2FIX(CL_EMAXFILES));
    rb_define_const(cClamAV, "CL_EFORMAT", INT2FIX(CL_EFORMAT));
#ifdef CL_EBYTECODE
    rb_define_const(cClamAV, "CL_EBYTECODE", INT2FIX(CL_EBYTECODE));
#endif

    /* db options */
    rb_define_const(cClamAV, "CL_DB_PHISHING", INT2FIX(CL_DB_PHISHING));
    rb_define_const(cClamAV, "CL_DB_PHISHING_URLS", INT2FIX(CL_DB_PHISHING_URLS));
    rb_define_const(cClamAV, "CL_DB_PUA", INT2FIX(CL_DB_PUA));
    rb_define_const(cClamAV, "CL_DB_CVDNOTMP", INT2FIX(CL_DB_CVDNOTMP)); /*  obsolete  */
    rb_define_const(cClamAV, "CL_DB_OFFICIAL", INT2FIX(CL_DB_OFFICIAL)); /*  internal  */
    rb_define_const(cClamAV, "CL_DB_PUA_MODE", INT2FIX(CL_DB_PUA_MODE));
    rb_define_const(cClamAV, "CL_DB_PUA_INCLUDE", INT2FIX(CL_DB_PUA_INCLUDE));
    rb_define_const(cClamAV, "CL_DB_PUA_EXCLUDE", INT2FIX(CL_DB_PUA_EXCLUDE));
    rb_define_const(cClamAV, "CL_DB_COMPILED", INT2FIX(CL_DB_COMPILED)); /*  internal  */
    rb_define_const(cClamAV, "CL_DB_DIRECTORY", INT2FIX(CL_DB_DIRECTORY)); /*  internal  */
#ifdef CL_DB_BYTECODE
    rb_define_const(cClamAV, "CL_DB_OFFICIAL_ONLY", INT2FIX(CL_DB_OFFICIAL_ONLY));
    rb_define_const(cClamAV, "CL_DB_BYTECODE", INT2FIX(CL_DB_BYTECODE));
    rb_define_const(cClamAV, "CL_DB_SIGNED", INT2FIX(CL_DB_SIGNED)); /*  internal  */
#endif

    /* recommended db settings */
    rb_define_const(cClamAV, "CL_DB_STDOPT", INT2FIX(CL_DB_STDOPT));

    /* scan options */
    rb_define_const(cClamAV, "CL_SCAN_RAW", INT2FIX(CL_SCAN_RAW));
    rb_define_const(cClamAV, "CL_SCAN_ARCHIVE", INT2FIX(CL_SCAN_ARCHIVE));
    rb_define_const(cClamAV, "CL_SCAN_MAIL", INT2FIX(CL_SCAN_MAIL));
    rb_define_const(cClamAV, "CL_SCAN_OLE2", INT2FIX(CL_SCAN_OLE2));
    rb_define_const(cClamAV, "CL_SCAN_BLOCKENCRYPTED", INT2FIX(CL_SCAN_BLOCKENCRYPTED));
    rb_define_const(cClamAV, "CL_SCAN_HTML", INT2FIX(CL_SCAN_HTML));
    rb_define_const(cClamAV, "CL_SCAN_PE", INT2FIX(CL_SCAN_PE));
    rb_define_const(cClamAV, "CL_SCAN_BLOCKBROKEN", INT2FIX(CL_SCAN_BLOCKBROKEN));
    rb_define_const(cClamAV, "CL_SCAN_MAILURL", INT2FIX(CL_SCAN_MAILURL)); /*  ignored  */
    rb_define_const(cClamAV, "CL_SCAN_BLOCKMAX", INT2FIX(CL_SCAN_BLOCKMAX)); /*  ignored  */
    rb_define_const(cClamAV, "CL_SCAN_ALGORITHMIC", INT2FIX(CL_SCAN_ALGORITHMIC));
    rb_define_const(cClamAV, "CL_SCAN_PHISHING_BLOCKSSL", INT2FIX(CL_SCAN_PHISHING_BLOCKSSL)); /*  ssl mismatches, not ssl by itself */
    rb_define_const(cClamAV, "CL_SCAN_PHISHING_BLOCKCLOAK", INT2FIX(CL_SCAN_PHISHING_BLOCKCLOAK));
    rb_define_const(cClamAV, "CL_SCAN_ELF", INT2FIX(CL_SCAN_ELF));
    rb_define_const(cClamAV, "CL_SCAN_PDF", INT2FIX(CL_SCAN_PDF));
    rb_define_const(cClamAV, "CL_SCAN_STRUCTURED", INT2FIX(CL_SCAN_STRUCTURED));
    rb_define_const(cClamAV, "CL_SCAN_STRUCTURED_SSN_NORMAL", INT2FIX(CL_SCAN_STRUCTURED_SSN_NORMAL));
    rb_define_const(cClamAV, "CL_SCAN_STRUCTURED_SSN_STRIPPED", INT2FIX(CL_SCAN_STRUCTURED_SSN_STRIPPED));
    rb_define_const(cClamAV, "CL_SCAN_PARTIAL_MESSAGE", INT2FIX(CL_SCAN_PARTIAL_MESSAGE));
    rb_define_const(cClamAV, "CL_SCAN_HEURISTIC_PRECEDENCE", INT2FIX(CL_SCAN_HEURISTIC_PRECEDENCE));

    /* recommended scan settings */
    rb_define_const(cClamAV, "CL_SCAN_STDOPT", INT2FIX(CL_SCAN_STDOPT));

    /* cl_countsigs options */
#ifdef CL_COUNTSIGS_OFFICIAL
    rb_define_const(cClamAV, "CL_COUNTSIGS_OFFICIAL", INT2FIX(CL_COUNTSIGS_OFFICIAL));
    rb_define_const(cClamAV, "CL_COUNTSIGS_UNOFFICIAL", INT2FIX(CL_COUNTSIGS_UNOFFICIAL));
    rb_define_const(cClamAV, "CL_COUNTSIGS_ALL", INT2FIX(CL_COUNTSIGS_ALL));
#endif

    rb_define_const(cClamAV, "CL_INIT_DEFAULT", INT2FIX(CL_INIT_DEFAULT));

    rb_define_const(cClamAV, "CL_ENGINE_MAX_SCANSIZE", INT2FIX(CL_ENGINE_MAX_SCANSIZE));        /*  uint64_t  */
    rb_define_const(cClamAV, "CL_ENGINE_MAX_FILESIZE", INT2FIX(CL_ENGINE_MAX_FILESIZE));        /*  uint64_t  */
    rb_define_const(cClamAV, "CL_ENGINE_MAX_RECURSION", INT2FIX(CL_ENGINE_MAX_RECURSION));      /*  uint32_t	 */
    rb_define_const(cClamAV, "CL_ENGINE_MAX_FILES", INT2FIX(CL_ENGINE_MAX_FILES));              /*  uint32_t  */
    rb_define_const(cClamAV, "CL_ENGINE_MIN_CC_COUNT", INT2FIX(CL_ENGINE_MIN_CC_COUNT));        /*  uint32_t  */
    rb_define_const(cClamAV, "CL_ENGINE_MIN_SSN_COUNT", INT2FIX(CL_ENGINE_MIN_SSN_COUNT));      /*  uint32_t  */
    rb_define_const(cClamAV, "CL_ENGINE_PUA_CATEGORIES", INT2FIX(CL_ENGINE_PUA_CATEGORIES));    /*  (char *)  */
    rb_define_const(cClamAV, "CL_ENGINE_DB_OPTIONS", INT2FIX(CL_ENGINE_DB_OPTIONS));            /*  uint32_t  */
    rb_define_const(cClamAV, "CL_ENGINE_DB_VERSION", INT2FIX(CL_ENGINE_DB_VERSION));            /*  uint32_t  */
    rb_define_const(cClamAV, "CL_ENGINE_DB_TIME", INT2FIX(CL_ENGINE_DB_TIME));                  /*  time_t  */
    rb_define_const(cClamAV, "CL_ENGINE_AC_ONLY", INT2FIX(CL_ENGINE_AC_ONLY));                  /*  uint32_t  */
    rb_define_const(cClamAV, "CL_ENGINE_AC_MINDEPTH", INT2FIX(CL_ENGINE_AC_MINDEPTH));          /*  uint32_t  */
    rb_define_const(cClamAV, "CL_ENGINE_AC_MAXDEPTH", INT2FIX(CL_ENGINE_AC_MAXDEPTH));          /*  uint32_t  */
    rb_define_const(cClamAV, "CL_ENGINE_TMPDIR", INT2FIX(CL_ENGINE_TMPDIR));                    /*  (char *)  */
    rb_define_const(cClamAV, "CL_ENGINE_KEEPTMP", INT2FIX(CL_ENGINE_KEEPTMP));                  /*  uint32_t  */
#ifdef CL_DB_BYTECODE
    rb_define_const(cClamAV, "CL_ENGINE_BYTECODE_SECURITY", INT2FIX(CL_ENGINE_BYTECODE_SECURITY)); /*  uint32_t  */
    rb_define_const(cClamAV, "CL_ENGINE_BYTECODE_TIMEOUT", INT2FIX(CL_ENGINE_BYTECODE_TIMEOUT)); /*  uint32_t  */

    rb_define_const(cClamAV, "CL_BYTECODE_TRUST_ALL", INT2FIX(CL_BYTECODE_TRUST_ALL));          /*  insecure, debug setting  */
    rb_define_const(cClamAV, "CL_BYTECODE_TRUST_SIGNED", INT2FIX(CL_BYTECODE_TRUST_SIGNED));    /*  default  */
    rb_define_const(cClamAV, "CL_BYTECODE_TRUST_NOTHING", INT2FIX(CL_BYTECODE_TRUST_NOTHING));  /*  paranoid setting  */
#endif