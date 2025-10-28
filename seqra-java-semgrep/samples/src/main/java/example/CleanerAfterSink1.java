package example;

import base.RuleSample;
import base.RuleSet;

@RuleSet("example/CleanerAfterSink1.yaml")
public abstract class CleanerAfterSink1 implements RuleSample {
    Object src() {
        return new Object();
    }

    void sink(Object o) {
    }

    void clean(Object o) {
    }

    static class PositiveSimple extends CleanerAfterSink1 {
        @Override
        public void entrypoint() {
            Object o = src();
            sink(o);
        }
    }

    static class NegativeSimple extends CleanerAfterSink1 {
        @Override
        public void entrypoint() {
            Object o = src();
            sink(o);
            clean(o);
        }
    }

    static class PositiveMultipleFunctions extends CleanerAfterSink1 {
        @Override
        public void entrypoint() {
            Object o = nestedSrc();
            nestedSink(o);
        }

        Object nestedSrc() {
            return src();
        }

        void nestedSink(Object o) {
            sink(o);
        }
    }

    static class NegativeMultipleFunctions extends CleanerAfterSink1 {
        @Override
        public void entrypoint() {
            Object o = nestedSrc();
            nestedSink(o);
            nestedClean(o);
        }

        Object nestedSrc() {
            return src();
        }

        void nestedSink(Object o) {
            sink(o);
        }

        void nestedClean(Object o) {
            clean(o);
        }
    }

    static class PositiveBranch extends CleanerAfterSink1 {
        boolean applyClean;

        @Override
        public void entrypoint() {
            Object o = nestedSrc();
            nestedSink(o);
            nestedClean(o);
        }

        Object nestedSrc() {
            return src();
        }

        void nestedSink(Object o) {
            sink(o);
        }

        void nestedClean(Object o) {
            if (applyClean) {
                clean(o);
            }
        }
    }

    static class NegativeBranch extends CleanerAfterSink1 {
        boolean applyClean;

        @Override
        public void entrypoint() {
            Object o = nestedSrc();
            nestedSink(o);
            nestedClean(o);
        }

        Object nestedSrc() {
            return src();
        }

        void nestedSink(Object o) {
            sink(o);
        }

        void nestedClean(Object o) {
            if (applyClean) {
                clean(o);
            } else {
                otherClean(o);
            }
        }

        void otherClean(Object o) {
            clean(o);
        }
    }
}
