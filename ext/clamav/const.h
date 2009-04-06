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


    /* db options */
    rb_define_const(cClamAV, "CL_DB_PHISHING", INT2FIX(CL_DB_PHISHING));
    rb_define_const(cClamAV, "CL_DB_PHISHING_URLS", INT2FIX(CL_DB_PHISHING_URLS));
    rb_define_const(cClamAV, "CL_DB_PUA", INT2FIX(CL_DB_PUA));
    rb_define_const(cClamAV, "CL_DB_CVDNOTMP", INT2FIX(CL_DB_CVDNOTMP));
    rb_define_const(cClamAV, "CL_DB_OFFICIAL", INT2FIX(CL_DB_OFFICIAL)); /*  internal  */
    rb_define_const(cClamAV, "CL_DB_PUA_MODE", INT2FIX(CL_DB_PUA_MODE));
    rb_define_const(cClamAV, "CL_DB_PUA_INCLUDE", INT2FIX(CL_DB_PUA_INCLUDE));
    rb_define_const(cClamAV, "CL_DB_PUA_EXCLUDE", INT2FIX(CL_DB_PUA_EXCLUDE));
    rb_define_const(cClamAV, "CL_DB_COMPILED", INT2FIX(CL_DB_COMPILED)); /*  internal  */

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
    rb_define_const(cClamAV, "CL_SCAN_MAILURL", INT2FIX(CL_SCAN_MAILURL));
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
