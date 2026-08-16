# Patched test-only equivalent using structured data.
require "json"

describe "legacy expression fixture" do
  it "reads a structured value" do
    expect(JSON.parse('{"value": 2}').fetch("value")).to eq(2)
  end
end
