#include <clamav.h>
#include <ruby.h>

static VALUE cClamAV;

struct ClamAV_R {
    struct cl_engine *root;
    struct cl_limits limits;
    unsigned int signo;
};

static void clamavr_free(struct ClamAV_R *ptr) {
    cl_free(ptr->root);
    xfree(ptr);
}

static VALUE clamavr_s_allocate(VALUE klass) {
    struct ClamAV_R *ptr = ALLOC(struct ClamAV_R);
    int ret;

    ptr->root = NULL;
    ptr->signo = 0;
    ret = cl_load(cl_retdbdir(), &ptr->root, &ptr->signo, CL_DB_STDOPT);
    if(ret) {
        rb_raise(rb_eRuntimeError, "cl_loaddbdir() error: %s\n", cl_strerror(ret));
    }
    cl_build(ptr->root);
    
    ptr->limits.maxscansize = 10 * 1024 * 1024;
    ptr->limits.maxfilesize = 10 * 1024 * 1024;
    ptr->limits.maxreclevel = 100;
    ptr->limits.maxfiles    = 1024;
    ptr->limits.archivememlim = 1;

    return Data_Wrap_Struct(klass, 0, clamavr_free, ptr);
}

static VALUE clamavr_initialize(VALUE self) {
    return self;
}

static VALUE clamavr_signo(VALUE self) {
    struct ClamAV_R *ptr;
    Data_Get_Struct(self, struct ClamAV_R, ptr);
    return UINT2NUM(ptr->signo);
}

static VALUE clamavr_scanfile(VALUE self, VALUE v_fname, VALUE v_options) {
    int ret;
    const char *virname;
    struct ClamAV_R *ptr;

    Check_Type(v_fname, T_STRING);
    Check_Type(v_options, T_FIXNUM);

    Data_Get_Struct(self, struct ClamAV_R, ptr);

    ret = cl_scanfile(RSTRING(v_fname)->ptr, &virname, NULL, ptr->root, &ptr->limits, FIX2INT(v_options));
    if (ret == CL_VIRUS) {
        return rb_str_new2(virname);
    } else {
        return INT2FIX(ret);
    }
}

void Init_clamav() {
    cClamAV =  rb_define_class("ClamAV", rb_cObject);
    rb_define_alloc_func(cClamAV, clamavr_s_allocate);
    rb_define_method(cClamAV, "initialize", clamavr_initialize, 0);

    rb_define_method(cClamAV, "scanfile", clamavr_scanfile, 2);
    rb_define_method(cClamAV, "signo", clamavr_signo, 0);

    /* return codes */
    rb_define_const(cClamAV, "CL_CLEAN", INT2FIX(CL_CLEAN));         /*  no virus found  */
    rb_define_const(cClamAV, "CL_VIRUS", INT2FIX(CL_VIRUS));         /*  virus(es) found  */
    rb_define_const(cClamAV, "CL_SUCCESS", INT2FIX(CL_SUCCESS));
    rb_define_const(cClamAV, "CL_BREAK", INT2FIX(CL_BREAK));

    rb_define_const(cClamAV, "CL_EMAXREC", INT2FIX(CL_EMAXREC));     /*  (internal) recursion limit exceeded  */
    rb_define_const(cClamAV, "CL_EMAXSIZE", INT2FIX(CL_EMAXSIZE));   /*  (internal) size limit exceeded  */
    rb_define_const(cClamAV, "CL_EMAXFILES", INT2FIX(CL_EMAXFILES)); /*  (internal) files limit exceeded  */
    rb_define_const(cClamAV, "CL_ERAR", INT2FIX(CL_ERAR));           /*  rar handler error  */
    rb_define_const(cClamAV, "CL_EZIP", INT2FIX(CL_EZIP));           /*  zip handler error  */
    rb_define_const(cClamAV, "CL_EGZIP", INT2FIX(CL_EGZIP));         /*  gzip handler error  */
    rb_define_const(cClamAV, "CL_EBZIP", INT2FIX(CL_EBZIP));         /*  bzip2 handler error  */
    rb_define_const(cClamAV, "CL_EOLE2", INT2FIX(CL_EOLE2));         /*  OLE2 handler error  */
    rb_define_const(cClamAV, "CL_EMSCOMP", INT2FIX(CL_EMSCOMP));     /*  MS Expand handler error  */
    rb_define_const(cClamAV, "CL_EMSCAB", INT2FIX(CL_EMSCAB));       /*  MS CAB module error  */
    rb_define_const(cClamAV, "CL_EACCES", INT2FIX(CL_EACCES));       /*  access denied  */
    rb_define_const(cClamAV, "CL_ENULLARG", INT2FIX(CL_ENULLARG));   /*  null argument  */
    rb_define_const(cClamAV, "CL_ETMPFILE", INT2FIX(CL_ETMPFILE));   /*  tmpfile() failed  */
    rb_define_const(cClamAV, "CL_EMEM", INT2FIX(CL_EMEM));           /*  memory allocation error  */
    rb_define_const(cClamAV, "CL_EOPEN", INT2FIX(CL_EOPEN));         /*  file open error  */
    rb_define_const(cClamAV, "CL_EMALFDB", INT2FIX(CL_EMALFDB));     /*  malformed database  */
    rb_define_const(cClamAV, "CL_EPATSHORT", INT2FIX(CL_EPATSHORT)); /*  pattern too short  */
    rb_define_const(cClamAV, "CL_ETMPDIR", INT2FIX(CL_ETMPDIR));     /*  mkdir() failed  */
    rb_define_const(cClamAV, "CL_ECVD", INT2FIX(CL_ECVD));           /*  not a CVD file (or broken)  */
    rb_define_const(cClamAV, "CL_ECVDEXTR", INT2FIX(CL_ECVDEXTR));   /*  CVD extraction failure  */
    rb_define_const(cClamAV, "CL_EMD5", INT2FIX(CL_EMD5));           /*  MD5 verification error  */
    rb_define_const(cClamAV, "CL_EDSIG", INT2FIX(CL_EDSIG));         /*  digital signature verification error  */
    rb_define_const(cClamAV, "CL_EIO", INT2FIX(CL_EIO));             /*  general I/O error  */
    rb_define_const(cClamAV, "CL_EFORMAT", INT2FIX(CL_EFORMAT));     /*  (internal) bad format or broken file  */
    rb_define_const(cClamAV, "CL_ESUPPORT", INT2FIX(CL_ESUPPORT));   /*  not supported data format  */
    rb_define_const(cClamAV, "CL_EARJ", INT2FIX(CL_EARJ));           /*  ARJ handler error  */

    /* db options */
    rb_define_const(cClamAV, "CL_DB_PHISHING", INT2FIX(CL_DB_PHISHING));
    rb_define_const(cClamAV, "CL_DB_ACONLY", INT2FIX(CL_DB_ACONLY)); /*  WARNING: only for developers  */
    rb_define_const(cClamAV, "CL_DB_PHISHING_URLS", INT2FIX(CL_DB_PHISHING_URLS));
    rb_define_const(cClamAV, "CL_DB_PUA", INT2FIX(CL_DB_PUA));
    rb_define_const(cClamAV, "CL_DB_CVDNOTMP", INT2FIX(CL_DB_CVDNOTMP));
    rb_define_const(cClamAV, "CL_DB_OFFICIAL", INT2FIX(CL_DB_OFFICIAL));
    rb_define_const(cClamAV, "CL_DB_PUA_MODE", INT2FIX(CL_DB_PUA_MODE));
    rb_define_const(cClamAV, "CL_DB_PUA_INCLUDE", INT2FIX(CL_DB_PUA_INCLUDE));
    rb_define_const(cClamAV, "CL_DB_PUA_EXCLUDE", INT2FIX(CL_DB_PUA_EXCLUDE));

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

}
