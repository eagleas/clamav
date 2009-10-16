#include <clamav.h>
#include <ruby.h>

static VALUE cClamAV;

struct ClamAV_R {
    struct cl_engine *root;
    int options;
    int db_options;
    struct cl_stat dbstat;
    unsigned int signo;
};

static void clamavr_free(struct ClamAV_R *ptr) {
    int ret;
    ret = cl_engine_free(ptr->root);
    if(ret != CL_SUCCESS) {
        rb_raise(rb_eRuntimeError, "cl_engine_free() error: %s\n", cl_strerror(ret));
    }
    xfree(ptr);
}

static VALUE clamavr_new(argc, argv, klass)
    int argc;
    VALUE *argv;
    VALUE klass;
{
    const char *v_fname;
    VALUE v_options;
    VALUE v_db_options;
    rb_scan_args(argc, argv, "02", &v_options, &v_db_options);
    if(NIL_P(v_options)){
      v_options = INT2FIX(CL_SCAN_STDOPT); /* default value */
    }
    if(NIL_P(v_db_options)){
      v_db_options = INT2FIX(CL_DB_STDOPT); /* default value */
    }

    int ret;
    ret = cl_init(FIX2INT(v_options));
    if(ret != CL_SUCCESS) {
        rb_raise(rb_eRuntimeError, "cl_init() error: %s\n", cl_strerror(ret));
    }
    struct ClamAV_R *ptr = ALLOC(struct ClamAV_R);
    ptr->root = cl_engine_new();
    if(ptr->root == NULL) {
        rb_raise(rb_eRuntimeError, "cl_engine_new() error: %s\n", cl_strerror(ret));
    };

    /* save options */
    ptr->options = v_options;
    ptr->db_options = v_db_options;

    ptr->signo = 0;

    const char *dbdir;
    dbdir = cl_retdbdir();

    ret = cl_load(dbdir, ptr->root, &ptr->signo, FIX2INT(v_db_options));
    if(ret != CL_SUCCESS) {
        rb_raise(rb_eRuntimeError, "cl_load() error: %s\n", cl_strerror(ret));
    }

    memset(&ptr->dbstat, 0, sizeof(struct cl_stat));
    cl_statinidir(dbdir, &ptr->dbstat);

    ret = cl_engine_compile(ptr->root);
    if(ret != CL_SUCCESS) {
        rb_raise(rb_eRuntimeError, "cl_engine_compile() error: %s\n", cl_strerror(ret));
    }
    return Data_Wrap_Struct(klass, 0, clamavr_free, ptr);
}

static VALUE clamavr_initialize(VALUE self) {
    return self;
}

static VALUE clamavr_setlimit(VALUE self, VALUE v_limit, VALUE v_value) {
    Check_Type(v_limit, T_FIXNUM);
    Check_Type(v_value, T_FIXNUM);

    struct ClamAV_R *ptr;
    Data_Get_Struct(self, struct ClamAV_R, ptr);

    int ret;
    ret = cl_engine_set_num(ptr->root, FIX2INT(v_limit), FIX2INT(v_value));
    if(ret != CL_SUCCESS) {
        rb_raise(rb_eRuntimeError, "cl_engine_set_num() error: %s\n", cl_strerror(ret));
    }
    return INT2FIX(ret);
}

static VALUE clamavr_getlimit(VALUE self, VALUE v_limit) {
    Check_Type(v_limit, T_FIXNUM);

    struct ClamAV_R *ptr;
    Data_Get_Struct(self, struct ClamAV_R, ptr);

    int ret;
    int err;
    ret = cl_engine_get_num(ptr->root, FIX2INT(v_limit), &err);
    if(err != CL_SUCCESS) {
        rb_raise(rb_eRuntimeError, "cl_engine_get_num() error: %s\n", cl_strerror(err));
    }
    return INT2NUM(ret);
}

static VALUE clamavr_setstring(VALUE self, VALUE v_param, VALUE v_value) {
    Check_Type(v_param, T_FIXNUM);
    Check_Type(v_value, T_STRING);

    struct ClamAV_R *ptr;
    Data_Get_Struct(self, struct ClamAV_R, ptr);

    int ret;
    ret = cl_engine_set_str(ptr->root, FIX2INT(v_param), RSTRING(v_value)->ptr);
    if(ret != CL_SUCCESS) {
        rb_raise(rb_eRuntimeError, "cl_engine_set_str() error: %s\n", cl_strerror(ret));
    }
    return INT2FIX(ret);
}

static VALUE clamavr_getstring(VALUE self, VALUE v_param) {
    Check_Type(v_param, T_FIXNUM);
    struct ClamAV_R *ptr;
    Data_Get_Struct(self, struct ClamAV_R, ptr);
    const char *result;
    int err;
    result = cl_engine_get_str(ptr->root, FIX2INT(v_param), &err);
    if(err != CL_SUCCESS) {
        rb_raise(rb_eRuntimeError, "cl_engine_get_str() error: %s\n", cl_strerror(err));
    }
    if(result == NULL){
      return Qnil;
    }
    return rb_str_new2(result);
}

static VALUE clamavr_signo(VALUE self) {
    struct ClamAV_R *ptr;
    Data_Get_Struct(self, struct ClamAV_R, ptr);
    return UINT2NUM(ptr->signo);
}

static VALUE clamavr_scanfile(argc, argv, klass)
    int argc;
    VALUE *argv;
    VALUE klass;
{
    struct ClamAV_R *ptr;
    Data_Get_Struct(klass, struct ClamAV_R, ptr);

    const char *v_fname;
    VALUE v_options;
    rb_scan_args(argc, argv, "11", &v_fname, &v_options);
    if(NIL_P(v_options)){
      v_options = ptr->options; /* stored value */
    }

    Check_Type(v_fname, T_STRING);
    Check_Type(v_options, T_FIXNUM);

    int ret;
    const char *virname;

    ret = cl_scanfile(RSTRING(v_fname)->ptr, &virname, NULL, ptr->root, FIX2INT(v_options));
    if (ret == CL_VIRUS) {
        return rb_str_new2(virname);
    } else {
        return INT2FIX(ret);
    }
}

static VALUE clamavr_dbreload(VALUE self) {
    struct ClamAV_R *ptr;
    Data_Get_Struct(self, struct ClamAV_R, ptr);

    int state;
    state = cl_statchkdir(&ptr->dbstat);
    if(state == 1) {
        const char *dbdir;
        dbdir = cl_retdbdir();
        int ret;
        ret = cl_load(dbdir, ptr->root, &ptr->signo, FIX2INT(ptr->db_options));
        if(ret != CL_SUCCESS) {
            rb_raise(rb_eRuntimeError, "cl_load() error: %s\n", cl_strerror(ret));
        }
        cl_statfree(&ptr->dbstat);
        cl_statinidir(dbdir, &ptr->dbstat);
    }
    return INT2FIX(state);
}

void Init_clamav() {
    cClamAV =  rb_define_class("ClamAV", rb_cObject);
    rb_define_singleton_method(cClamAV, "new", clamavr_new, -1);
    rb_define_method(cClamAV, "initialize", clamavr_initialize, 0);
    rb_define_method(cClamAV, "scanfile", clamavr_scanfile, -1);
    rb_define_method(cClamAV, "signo", clamavr_signo, 0);
    rb_define_method(cClamAV, "setlimit", clamavr_setlimit, 2);
    rb_define_method(cClamAV, "getlimit", clamavr_getlimit, 1);
    rb_define_method(cClamAV, "setstring", clamavr_setstring, 2);
    rb_define_method(cClamAV, "getstring", clamavr_getstring, 1);
    rb_define_method(cClamAV, "reload", clamavr_dbreload, 0);

#include <const.h>
}
