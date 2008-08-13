require File.dirname(__FILE__) + '/../spec_helper'

class ClamAV

  describe "class" do

    before(:each) do                                                                                                   
      @clam = ClamAV.new()
    end

    it "should be instance of Clamav" do
      @clam.should be_instance_of(ClamAV)
    end

    FILES = {
      'robots.txt' => CL_CLEAN,
      'eicar.com'  => 'Eicar-Test-Signature', # EICAR
      'test.txt'   => 'Eicar-Test-Signature', # EICAR in text/plain
      'clam.cab'      => 'ClamAV-Test-File',
      'clam.exe'      => 'ClamAV-Test-File',
      'clam.exe.bz2'  => 'ClamAV-Test-File',
      'clam.zip'      => 'ClamAV-Test-File',
      'clam-v2.rar'   => 'ClamAV-Test-File',
      'clam-v3.rar'   => 'ClamAV-Test-File',
      'clam-p.rar'    => 'Encrypted.RAR',  # encripted RAR
      # Bug in ClamAV https://wwws.clamav.net/bugzilla/show_bug.cgi?id=1134
      # 'clam-ph.rar'    => 'Encrypted.RAR', # encripted RAR with encrypted both file data and headers
      'program.doc'   => 'W97M.Class.EB',
      'Программа.doc' => 'W97M.Class.EB', # filename in UTF-8
    }

    FILES.each do |file, result|
      it "should scan #{file} with result #{result.to_s}" do
        @clam.scanfile(File.join(File.dirname(__FILE__), "../clamav-testfiles/", file), 
          CL_SCAN_STDOPT | CL_SCAN_BLOCKENCRYPTED).should == result
      end
    end

  end
end
