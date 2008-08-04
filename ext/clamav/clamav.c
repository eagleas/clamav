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
    
    ptr->limits.maxreclevel = 100;
    ptr->limits.maxfiles    = 1024;
    ptr->limits.maxmailrec  = 5;
    ptr->limits.archivememlim = 1;
    ptr->limits.maxfilesize = 10 * 1024 * 1024;

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

    rb_define_const(cClamAV, "CL_VIRUS", INT2FIX(CL_VIRUS));
    rb_define_const(cClamAV, "CL_SUCCESS", INT2FIX(CL_SUCCESS));
    rb_define_const(cClamAV, "CL_BREAK", INT2FIX(CL_BREAK));
    rb_define_const(cClamAV, "CL_EMAXREC", INT2FIX(CL_EMAXREC));
    rb_define_const(cClamAV, "CL_EMAXSIZE", INT2FIX(CL_EMAXSIZE));
    rb_define_const(cClamAV, "CL_EMAXFILES", INT2FIX(CL_EMAXFILES));
    rb_define_const(cClamAV, "CL_ERAR", INT2FIX(CL_ERAR));
    rb_define_const(cClamAV, "CL_EZIP", INT2FIX(CL_EZIP));
    rb_define_const(cClamAV, "CL_EGZIP", INT2FIX(CL_EGZIP));
    rb_define_const(cClamAV, "CL_EBZIP", INT2FIX(CL_EBZIP));
    rb_define_const(cClamAV, "CL_EOLE2", INT2FIX(CL_EOLE2));
    rb_define_const(cClamAV, "CL_EMSCOMP", INT2FIX(CL_EMSCOMP));
    rb_define_const(cClamAV, "CL_EMSCAB", INT2FIX(CL_EMSCAB));
    rb_define_const(cClamAV, "CL_EACCES", INT2FIX(CL_EACCES));
    rb_define_const(cClamAV, "CL_ENULLARG", INT2FIX(CL_ENULLARG));
    rb_define_const(cClamAV, "CL_ETMPFILE", INT2FIX(CL_ETMPFILE));
    rb_define_const(cClamAV, "CL_EFSYNC", INT2FIX(CL_EFSYNC));
    rb_define_const(cClamAV, "CL_EMEM", INT2FIX(CL_EMEM));
    rb_define_const(cClamAV, "CL_EOPEN", INT2FIX(CL_EOPEN));
    rb_define_const(cClamAV, "CL_EMALFDB", INT2FIX(CL_EMALFDB));
    rb_define_const(cClamAV, "CL_EPATSHORT", INT2FIX(CL_EPATSHORT));
    rb_define_const(cClamAV, "CL_ETMPDIR", INT2FIX(CL_ETMPDIR));
    rb_define_const(cClamAV, "CL_ECVD", INT2FIX(CL_ECVD));
    rb_define_const(cClamAV, "CL_ECVDEXTR", INT2FIX(CL_ECVDEXTR));
    rb_define_const(cClamAV, "CL_EMD5", INT2FIX(CL_EMD5));
    rb_define_const(cClamAV, "CL_EDSIG", INT2FIX(CL_EDSIG));
    rb_define_const(cClamAV, "CL_EIO", INT2FIX(CL_EIO));
    rb_define_const(cClamAV, "CL_EFORMAT", INT2FIX(CL_EFORMAT));
    rb_define_const(cClamAV, "CL_ESUPPORT", INT2FIX(CL_ESUPPORT));
    rb_define_const(cClamAV, "CL_ELOCKDB", INT2FIX(CL_ELOCKDB));
/*    rb_define_const(cClamAV, "CL_ENCINIT", INT2FIX(CL_ENCINIT));
    rb_define_const(cClamAV, "CL_ENCIO", INT2FIX(CL_ENCIO));
    rb_define_const(cClamAV, "CL_DB_NCORE", INT2FIX(CL_DB_NCORE)); */
    rb_define_const(cClamAV, "CL_DB_PHISHING", INT2FIX(CL_DB_PHISHING));
    rb_define_const(cClamAV, "CL_DB_ACONLY", INT2FIX(CL_DB_ACONLY));
    rb_define_const(cClamAV, "CL_DB_PHISHING_URLS", INT2FIX(CL_DB_PHISHING_URLS));
    rb_define_const(cClamAV, "CL_DB_STDOPT", INT2FIX(CL_DB_STDOPT));
    rb_define_const(cClamAV, "CL_SCAN_RAW", INT2FIX(CL_SCAN_RAW));
    rb_define_const(cClamAV, "CL_SCAN_ARCHIVE", INT2FIX(CL_SCAN_ARCHIVE));
    rb_define_const(cClamAV, "CL_SCAN_MAIL", INT2FIX(CL_SCAN_MAIL));
    rb_define_const(cClamAV, "CL_SCAN_OLE2", INT2FIX(CL_SCAN_OLE2));
    rb_define_const(cClamAV, "CL_SCAN_BLOCKENCRYPTED", INT2FIX(CL_SCAN_BLOCKENCRYPTED));
    rb_define_const(cClamAV, "CL_SCAN_HTML", INT2FIX(CL_SCAN_HTML));
    rb_define_const(cClamAV, "CL_SCAN_PE", INT2FIX(CL_SCAN_PE));
    rb_define_const(cClamAV, "CL_SCAN_BLOCKBROKEN", INT2FIX(CL_SCAN_BLOCKBROKEN));
    rb_define_const(cClamAV, "CL_SCAN_MAILURL", INT2FIX(CL_SCAN_MAILURL));
    rb_define_const(cClamAV, "CL_SCAN_BLOCKMAX", INT2FIX(CL_SCAN_BLOCKMAX));
    rb_define_const(cClamAV, "CL_SCAN_ALGORITHMIC", INT2FIX(CL_SCAN_ALGORITHMIC));
    rb_define_const(cClamAV, "CL_SCAN_PHISHING_DOMAINLIST", INT2FIX(CL_SCAN_PHISHING_DOMAINLIST));
    rb_define_const(cClamAV, "CL_SCAN_PHISHING_BLOCKSSL", INT2FIX(CL_SCAN_PHISHING_BLOCKSSL));
    rb_define_const(cClamAV, "CL_SCAN_PHISHING_BLOCKCLOAK", INT2FIX(CL_SCAN_PHISHING_BLOCKCLOAK));
    rb_define_const(cClamAV, "CL_SCAN_ELF", INT2FIX(CL_SCAN_ELF));
    rb_define_const(cClamAV, "CL_SCAN_PDF", INT2FIX(CL_SCAN_PDF));
    rb_define_const(cClamAV, "CL_SCAN_STDOPT", INT2FIX(CL_SCAN_STDOPT));
    rb_define_const(cClamAV, "CL_RAW", INT2FIX(CL_RAW));
    rb_define_const(cClamAV, "CL_ARCHIVE", INT2FIX(CL_ARCHIVE));
    rb_define_const(cClamAV, "CL_MAIL", INT2FIX(CL_MAIL));
    rb_define_const(cClamAV, "CL_OLE2", INT2FIX(CL_OLE2));
    rb_define_const(cClamAV, "CL_ENCRYPTED", INT2FIX(CL_ENCRYPTED));
}
