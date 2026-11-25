// Original synthetic source, not compiled. No I/O or external calls.
namespace PreparationFixtures {
    public abstract class Sample {
        public abstract int MissingBody(int value);
        public int Same(int value) { return value + 1; }
        public int Same(short value) { return value + 2; }
        public int Other(int value) { return value + 3; }
        public int WithException(int value) {
            try { return 12 / value; }
            catch (System.DivideByZeroException) { return 0; }
        }
    }
    public sealed class Generic<T> {
        public T Identity(T value) { return value; }
    }
}
