require File.dirname(__FILE__) + '/../spec_helper'

describe ClamAV, "class" do

  before(:each) do                                                                                                   
    @clam = ClamAV.new()
  end

  it "should be instance of Clamav" do
    @clam.should be_instance_of(ClamAV)
  end

end
