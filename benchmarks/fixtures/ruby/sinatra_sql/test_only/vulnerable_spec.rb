# Deliberately vulnerable test-only benchmark case. Never execute it.
describe "legacy expression fixture" do
  it "evaluates an external expression" do
    expect(eval(ENV.fetch("BENCHMARK_EXPRESSION"))).to eq(2)
  end
end
