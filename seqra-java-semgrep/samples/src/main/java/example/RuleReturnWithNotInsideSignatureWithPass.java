package example;

import base.EntryPoint;
import base.RuleSample;
import base.RuleSet;

@RuleSet("example/RuleReturnWithNotInsideSignature.yaml")
public abstract class RuleReturnWithNotInsideSignatureWithPass implements RuleSample {
    public Object clean(Object o) {
        return new Object();
    }

    public static class Positive extends RuleReturnWithNotInsideSignatureWithPass {

        @Override
        public void entrypoint() {
            method("data");
        }

        @EntryPoint
        public Object method(Object o) {
            return o;
        }
    }

    public static class Negative extends RuleReturnWithNotInsideSignatureWithPass {

        @Override
        public void entrypoint() {
            method("data");
        }

        @EntryPoint
        public Object method(Object o) {
            return clean(o);
        }
    }
}
