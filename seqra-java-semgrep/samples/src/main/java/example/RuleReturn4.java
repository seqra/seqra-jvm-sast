package example;

import base.RuleSample;
import base.RuleSet;

@RuleSet("example/RuleReturn4.yaml")
public abstract class RuleReturn4 implements RuleSample {
    static class Positive extends RuleReturn4 {
        @Override
        public void entrypoint() {
            String ret = returned();
            sink(ret);
        }

        private String returned() {
            String a = src();
            return a;
        }
    }

    static class Negative extends RuleReturn4 {
        @Override
        public void entrypoint() {
            String ret = returned();
            sink(ret);
        }

        private String returned() {
            String a = src();
            clean(a);
            return a;
        }
    }

    String src() { return "tainted"; }
    void clean(String s) {}
    void sink(String s) {}
}