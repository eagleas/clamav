#!/usr/local/bin/ruby -Ks

require "mkmf"

dir_config("clamav")

if have_header("clamav.h") && have_library('clamav', 'cl_loaddbdir')
  create_makefile("clamav")
end
