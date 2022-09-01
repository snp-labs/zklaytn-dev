package bls12381

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"
)

func TestGt(t *testing.T) {
	//rev := []byte{49, 102, 103, 59, 56, 73, 228, 253, 30, 126, 228, 175, 36, 170, 142, 212, 67, 245, 109, 253, 107, 104, 255, 222, 68, 53, 169, 44, 215, 164, 172, 59, 199, 126, 26, 208, 203, 114, 134, 6, 207, 8, 191, 99, 134, 229, 65, 15, 239, 227, 15, 45, 36, 240, 8, 145, 203, 69, 98, 6, 5, 252, 250, 164, 41, 38, 135, 179, 167, 219, 124, 28, 5, 84, 169, 53, 121, 232, 137, 161, 33, 253, 143, 114, 100, 155, 36, 2, 153, 106, 8, 77, 35, 129, 197, 4, 162, 153, 90, 194, 160, 145, 34, 190, 217, 253, 159, 160, 197, 16, 168, 123, 16, 41, 8, 54, 173, 6, 200, 32, 51, 151, 181, 106, 120, 233, 160, 198, 28, 119, 229, 108, 203, 79, 27, 195, 211, 252, 174, 167, 85, 15, 53, 3, 87, 186, 226, 51, 115, 180, 147, 27, 201, 250, 50, 30, 136, 72, 239, 120, 137, 78, 152, 123, 255, 21, 13, 125, 103, 26, 238, 48, 179, 147, 26, 200, 197, 14, 11, 59, 8, 104, 239, 252, 56, 191, 72, 205, 36, 180, 184, 17, 26, 171, 213, 213, 194, 225, 42, 16, 184, 240, 2, 255, 104, 27, 253, 27, 46, 224, 191, 97, 157, 128, 210, 167, 149, 235, 34, 242, 170, 123, 133, 213, 255, 182, 113, 167, 12, 148, 128, 159, 13, 175, 197, 183, 62, 162, 251, 6, 157, 232, 126, 228, 38, 130, 148, 15, 62, 112, 168, 134, 131, 213, 18, 187, 44, 63, 183, 178, 67, 77, 165, 222, 219, 178, 208, 179, 251, 132, 135, 200, 77, 160, 213, 195, 21, 189, 214, 156, 70, 251, 5, 210, 55, 99, 242, 25, 182, 180, 69, 64, 98, 233, 234, 139, 167, 140, 92, 163, 202, 218, 247, 35, 139, 71, 186, 206, 92, 229, 97, 128, 74, 225, 107, 143, 75, 99, 218, 70, 69, 184, 69, 122, 147, 121, 60, 189, 100, 167, 37, 79, 21, 7, 129, 1, 165, 170, 151, 181, 31, 28, 173, 29, 67, 216, 170, 187, 255, 77, 195, 25, 199, 154, 88, 202, 252, 3, 82, 24, 116, 124, 47, 117, 218, 248, 242, 251, 124, 0, 196, 77, 168, 91, 18, 145, 19, 23, 61, 71, 34, 245, 178, 1, 79, 147, 25, 60, 236, 33, 80, 49, 177, 115, 153, 87, 122, 29, 229, 255, 31, 91, 6, 102, 189, 216, 144, 124, 97, 167, 101, 30, 78, 121, 224, 55, 41, 81, 80, 90, 7, 250, 115, 194, 87, 136, 219, 110, 184, 2, 53, 25, 135, 62, 194, 158, 132, 76, 28, 136, 140, 179, 150, 147, 48, 87, 255, 221, 84, 27, 3, 165, 34, 14, 218, 22, 178, 179, 166, 114, 142, 166, 120, 3, 76, 227, 156, 104, 57, 242, 3, 151, 32, 45, 124, 92, 68, 187, 104, 19, 15, 23, 160, 234, 152, 42, 136, 89, 29, 159, 67, 80, 62, 148, 168, 241, 171, 175, 46, 69, 137, 246, 90, 175, 183, 146, 60, 72, 69, 64, 168, 104, 136, 52, 50, 165, 198, 14, 117, 134, 11, 17, 229, 70, 91, 28, 154, 8, 182, 137, 23, 202, 170, 5, 67, 168, 8, 197, 57, 8, 246, 148, 209, 182, 231, 179, 141, 233, 12, 233, 216, 61, 80, 92, 161, 239, 27, 68, 45, 39, 39, 215, 208, 104, 49, 216, 178, 167, 146, 10, 252, 113, 216, 235, 80, 18}

	gt_2 := []byte{4, 170, 131, 153, 92, 79, 65, 157, 50, 106, 109, 75, 208, 194, 123, 81, 23, 238, 114, 77, 15, 8, 160, 194, 54, 68, 178, 143, 122, 167, 143, 76, 0, 27, 228, 32, 193, 80, 85, 237, 44, 97, 222, 53, 175, 28, 104, 123, 13, 202, 250, 40, 241, 141, 213, 243, 35, 108, 74, 95, 15, 104, 223, 70, 7, 251, 117, 136, 4, 113, 131, 31, 36, 129, 200, 81, 229, 52, 133, 246, 3, 0, 212, 191, 211, 32, 50, 142, 101, 224, 204, 12, 58, 42, 64, 62, 11, 110, 16, 164, 170, 119, 224, 168, 44, 238, 99, 97, 96, 214, 169, 99, 5, 99, 151, 210, 143, 55, 14, 13, 199, 253, 255, 85, 177, 52, 109, 82, 90, 92, 102, 240, 116, 57, 242, 151, 102, 79, 11, 105, 23, 228, 219, 104, 20, 87, 42, 210, 216, 236, 153, 244, 107, 29, 215, 79, 20, 32, 88, 127, 208, 88, 18, 25, 175, 166, 183, 38, 206, 233, 192, 126, 178, 226, 117, 28, 56, 159, 65, 233, 58, 118, 248, 200, 240, 219, 204, 11, 31, 165, 16, 138, 21, 207, 74, 229, 26, 197, 19, 231, 154, 61, 46, 87, 253, 15, 240, 210, 54, 76, 221, 254, 180, 15, 4, 238, 58, 164, 169, 175, 182, 247, 58, 196, 75, 82, 48, 31, 191, 219, 162, 91, 192, 153, 189, 145, 91, 82, 92, 36, 23, 101, 125, 186, 176, 96, 159, 158, 3, 63, 8, 252, 211, 31, 80, 175, 190, 204, 12, 244, 90, 87, 60, 236, 58, 172, 17, 97, 156, 146, 228, 64, 76, 45, 82, 124, 127, 228, 94, 153, 98, 44, 9, 245, 204, 43, 216, 164, 22, 154, 5, 96, 106, 80, 209, 184, 16, 161, 204, 215, 138, 247, 170, 164, 188, 200, 85, 60, 23, 124, 150, 185, 85, 225, 65, 148, 178, 61, 0, 197, 158, 106, 211, 154, 130, 149, 80, 246, 25, 132, 221, 199, 177, 116, 122, 18, 14, 255, 168, 222, 231, 175, 119, 248, 154, 66, 240, 109, 124, 87, 97, 59, 50, 177, 21, 6, 196, 224, 178, 12, 104, 9, 102, 97, 95, 8, 73, 118, 227, 146, 83, 28, 234, 174, 168, 108, 82, 238, 175, 249, 179, 38, 202, 89, 18, 60, 131, 29, 170, 58, 17, 24, 35, 99, 49, 242, 244, 206, 8, 135, 57, 12, 176, 179, 179, 225, 172, 66, 249, 52, 172, 207, 21, 19, 94, 22, 171, 157, 207, 132, 233, 28, 104, 40, 110, 95, 31, 238, 149, 2, 159, 225, 9, 223, 54, 150, 248, 12, 152, 242, 49, 218, 131, 201, 173, 185, 80, 26, 238, 12, 190, 162, 203, 98, 12, 41, 242, 212, 49, 86, 133, 129, 155, 121, 200, 81, 224, 151, 50, 59, 163, 44, 86, 226, 122, 5, 155, 121, 17, 69, 25, 64, 30, 103, 88, 97, 69, 29, 203, 157, 186, 107, 215, 158, 79, 116, 7, 172, 243, 71, 29, 172, 74, 1, 131, 6, 105, 29, 181, 23, 135, 155, 23, 154, 137, 36, 180, 80, 169, 45, 144, 15, 54, 29, 51, 91, 73, 125, 13, 184, 196, 87, 98, 101, 39, 80, 135, 34, 34, 110, 155, 216, 37, 131, 76, 56, 84, 198, 210, 175, 193, 209, 151, 40, 31, 35, 181, 219, 230, 55, 55, 80, 246, 231, 46, 208, 38, 84, 75, 232, 0, 1, 92, 58, 98, 22}
	// g := NewPairingEngine()
	// g1 := NewG1().One()
	// g2 := NewG2().One()
	// g.AddPair(g1, g2)
	// fp_ := newFp12(nil)
	fmt.Println(hex.EncodeToString(gt_2))
	//gts, err := gt.FromBytes(rev)

}
func TestFpSerialization(t *testing.T) {
	t.Run("zero", func(t *testing.T) {
		in := make([]byte, 48)
		fe, err := fromBytes(in)
		if err != nil {
			t.Fatal(err)
		}
		if !fe.isZero() {
			t.Fatal("bad serialization")
		}
		if !bytes.Equal(in, toBytes(fe)) {
			t.Fatal("bad serialization")
		}
	})
	t.Run("bytes", func(t *testing.T) {
		for i := 0; i < fuz; i++ {
			a, _ := new(fe).rand(rand.Reader)
			b, err := fromBytes(toBytes(a))
			if err != nil {
				t.Fatal(err)
			}
			if !a.equal(b) {
				t.Fatal("bad serialization")
			}
		}
	})
	t.Run("string", func(t *testing.T) {
		for i := 0; i < fuz; i++ {
			a, _ := new(fe).rand(rand.Reader)
			b, err := fromString(toString(a))
			if err != nil {
				t.Fatal(err)
			}
			if !a.equal(b) {
				t.Fatal("bad encoding or decoding")
			}
		}
	})
	t.Run("big", func(t *testing.T) {
		for i := 0; i < fuz; i++ {
			a, _ := new(fe).rand(rand.Reader)
			b, err := fromBig(toBig(a))
			if err != nil {
				t.Fatal(err)
			}
			if !a.equal(b) {
				t.Fatal("bad encoding or decoding")
			}
		}
	})
}

func TestFpAdditionCrossAgainstBigInt(t *testing.T) {
	for i := 0; i < fuz; i++ {
		a, _ := new(fe).rand(rand.Reader)
		b, _ := new(fe).rand(rand.Reader)
		c := new(fe)
		big_a := toBig(a)
		big_b := toBig(b)
		big_c := new(big.Int)
		add(c, a, b)
		out_1 := toBytes(c)
		out_2 := padBytes(big_c.Add(big_a, big_b).Mod(big_c, modulus.big()).Bytes(), 48)
		if !bytes.Equal(out_1, out_2) {
			t.Fatal("cross test against big.Int is not satisfied A")
		}
		double(c, a)
		out_1 = toBytes(c)
		out_2 = padBytes(big_c.Add(big_a, big_a).Mod(big_c, modulus.big()).Bytes(), 48)
		if !bytes.Equal(out_1, out_2) {
			t.Fatal("cross test against big.Int is not satisfied B")
		}
		sub(c, a, b)
		out_1 = toBytes(c)
		out_2 = padBytes(big_c.Sub(big_a, big_b).Mod(big_c, modulus.big()).Bytes(), 48)
		if !bytes.Equal(out_1, out_2) {
			t.Fatal("cross test against big.Int is not satisfied C")
		}
		neg(c, a)
		out_1 = toBytes(c)
		out_2 = padBytes(big_c.Neg(big_a).Mod(big_c, modulus.big()).Bytes(), 48)
		if !bytes.Equal(out_1, out_2) {
			t.Fatal("cross test against big.Int is not satisfied D")
		}
	}
}

func TestFpAdditionCrossAgainstBigIntAssigned(t *testing.T) {
	for i := 0; i < fuz; i++ {
		a, _ := new(fe).rand(rand.Reader)
		b, _ := new(fe).rand(rand.Reader)
		big_a, big_b := toBig(a), toBig(b)
		addAssign(a, b)
		out_1 := toBytes(a)
		out_2 := padBytes(big_a.Add(big_a, big_b).Mod(big_a, modulus.big()).Bytes(), 48)
		if !bytes.Equal(out_1, out_2) {
			t.Fatal("cross test against big.Int is not satisfied A")
		}
		a, _ = new(fe).rand(rand.Reader)
		big_a = toBig(a)
		doubleAssign(a)
		out_1 = toBytes(a)
		out_2 = padBytes(big_a.Add(big_a, big_a).Mod(big_a, modulus.big()).Bytes(), 48)
		if !bytes.Equal(out_1, out_2) {
			t.Fatal("cross test against big.Int is not satisfied B")
		}
		a, _ = new(fe).rand(rand.Reader)
		b, _ = new(fe).rand(rand.Reader)
		big_a, big_b = toBig(a), toBig(b)
		subAssign(a, b)
		out_1 = toBytes(a)
		out_2 = padBytes(big_a.Sub(big_a, big_b).Mod(big_a, modulus.big()).Bytes(), 48)
		if !bytes.Equal(out_1, out_2) {
			t.Fatal("cross test against big.Int is not satisfied A")
		}
	}
}

func TestFpAdditionProperties(t *testing.T) {
	for i := 0; i < fuz; i++ {
		zero := new(fe).zero()
		a, _ := new(fe).rand(rand.Reader)
		b, _ := new(fe).rand(rand.Reader)
		c_1, c_2 := new(fe), new(fe)
		add(c_1, a, zero)
		if !c_1.equal(a) {
			t.Fatal("a + 0 == a")
		}
		sub(c_1, a, zero)
		if !c_1.equal(a) {
			t.Fatal("a - 0 == a")
		}
		double(c_1, zero)
		if !c_1.equal(zero) {
			t.Fatal("2 * 0 == 0")
		}
		neg(c_1, zero)
		if !c_1.equal(zero) {
			t.Fatal("-0 == 0")
		}
		sub(c_1, zero, a)
		neg(c_2, a)
		if !c_1.equal(c_2) {
			t.Fatal("0-a == -a")
		}
		double(c_1, a)
		add(c_2, a, a)
		if !c_1.equal(c_2) {
			t.Fatal("2 * a == a + a")
		}
		add(c_1, a, b)
		add(c_2, b, a)
		if !c_1.equal(c_2) {
			t.Fatal("a + b = b + a")
		}
		sub(c_1, a, b)
		sub(c_2, b, a)
		neg(c_2, c_2)
		if !c_1.equal(c_2) {
			t.Fatal("a - b = - ( b - a )")
		}
		c_x, _ := new(fe).rand(rand.Reader)
		add(c_1, a, b)
		add(c_1, c_1, c_x)
		add(c_2, a, c_x)
		add(c_2, c_2, b)
		if !c_1.equal(c_2) {
			t.Fatal("(a + b) + c == (a + c ) + b")
		}
		sub(c_1, a, b)
		sub(c_1, c_1, c_x)
		sub(c_2, a, c_x)
		sub(c_2, c_2, b)
		if !c_1.equal(c_2) {
			t.Fatal("(a - b) - c == (a - c ) -b")
		}
	}
}

func TestFpAdditionPropertiesAssigned(t *testing.T) {
	for i := 0; i < fuz; i++ {
		zero := new(fe).zero()
		a, b := new(fe), new(fe)
		_, _ = a.rand(rand.Reader)
		b.set(a)
		addAssign(a, zero)
		if !a.equal(b) {
			t.Fatal("a + 0 == a")
		}
		subAssign(a, zero)
		if !a.equal(b) {
			t.Fatal("a - 0 == a")
		}
		a.set(zero)
		doubleAssign(a)
		if !a.equal(zero) {
			t.Fatal("2 * 0 == 0")
		}
		a.set(zero)
		subAssign(a, b)
		neg(b, b)
		if !a.equal(b) {
			t.Fatal("0-a == -a")
		}
		_, _ = a.rand(rand.Reader)
		b.set(a)
		doubleAssign(a)
		addAssign(b, b)
		if !a.equal(b) {
			t.Fatal("2 * a == a + a")
		}
		_, _ = a.rand(rand.Reader)
		_, _ = b.rand(rand.Reader)
		c_1, c_2 := new(fe).set(a), new(fe).set(b)
		addAssign(c_1, b)
		addAssign(c_2, a)
		if !c_1.equal(c_2) {
			t.Fatal("a + b = b + a")
		}
		_, _ = a.rand(rand.Reader)
		_, _ = b.rand(rand.Reader)
		c_1.set(a)
		c_2.set(b)
		subAssign(c_1, b)
		subAssign(c_2, a)
		neg(c_2, c_2)
		if !c_1.equal(c_2) {
			t.Fatal("a - b = - ( b - a )")
		}
		_, _ = a.rand(rand.Reader)
		_, _ = b.rand(rand.Reader)
		c, _ := new(fe).rand(rand.Reader)
		a0 := new(fe).set(a)
		addAssign(a, b)
		addAssign(a, c)
		addAssign(b, c)
		addAssign(b, a0)
		if !a.equal(b) {
			t.Fatal("(a + b) + c == (b + c) + a")
		}
		_, _ = a.rand(rand.Reader)
		_, _ = b.rand(rand.Reader)
		_, _ = c.rand(rand.Reader)
		a0.set(a)
		subAssign(a, b)
		subAssign(a, c)
		subAssign(a0, c)
		subAssign(a0, b)
		if !a.equal(a0) {
			t.Fatal("(a - b) - c == (a - c) -b")
		}
	}
}

func TestFpLazyOperations(t *testing.T) {
	for i := 0; i < fuz; i++ {
		a, _ := new(fe).rand(rand.Reader)
		b, _ := new(fe).rand(rand.Reader)
		c, _ := new(fe).rand(rand.Reader)
		c0 := new(fe)
		c1 := new(fe)
		ladd(c0, a, b)
		add(c1, a, b)
		mul(c0, c0, c)
		mul(c1, c1, c)
		if !c0.equal(c1) {
			// l+ operator stands for lazy addition
			t.Fatal("(a + b) * c == (a l+ b) * c")
		}
		_, _ = a.rand(rand.Reader)
		b.set(a)
		ldouble(a, a)
		ladd(b, b, b)
		if !a.equal(b) {
			t.Fatal("2 l* a = a l+ a")
		}
		_, _ = a.rand(rand.Reader)
		_, _ = b.rand(rand.Reader)
		_, _ = c.rand(rand.Reader)
		a0 := new(fe).set(a)
		lsubAssign(a, b)
		laddAssign(a, &modulus)
		mul(a, a, c)
		subAssign(a0, b)
		mul(a0, a0, c)
		if !a.equal(a0) {
			t.Fatal("((a l- b) + p) * c = (a-b) * c")
		}
	}
}

func TestFpMultiplicationCrossAgainstBigInt(t *testing.T) {
	for i := 0; i < fuz; i++ {
		a, _ := new(fe).rand(rand.Reader)
		b, _ := new(fe).rand(rand.Reader)
		c := new(fe)
		big_a := toBig(a)
		big_b := toBig(b)
		big_c := new(big.Int)
		mul(c, a, b)
		out_1 := toBytes(c)
		out_2 := padBytes(big_c.Mul(big_a, big_b).Mod(big_c, modulus.big()).Bytes(), 48)
		if !bytes.Equal(out_1, out_2) {
			t.Fatal("cross test against big.Int is not satisfied")
		}
	}
}

func TestFpMultiplicationProperties(t *testing.T) {
	for i := 0; i < fuz; i++ {
		a, _ := new(fe).rand(rand.Reader)
		b, _ := new(fe).rand(rand.Reader)
		zero, one := new(fe).zero(), new(fe).one()
		c_1, c_2 := new(fe), new(fe)
		mul(c_1, a, zero)
		if !c_1.equal(zero) {
			t.Fatal("a * 0 == 0")
		}
		mul(c_1, a, one)
		if !c_1.equal(a) {
			t.Fatal("a * 1 == a")
		}
		mul(c_1, a, b)
		mul(c_2, b, a)
		if !c_1.equal(c_2) {
			t.Fatal("a * b == b * a")
		}
		c_x, _ := new(fe).rand(rand.Reader)
		mul(c_1, a, b)
		mul(c_1, c_1, c_x)
		mul(c_2, c_x, b)
		mul(c_2, c_2, a)
		if !c_1.equal(c_2) {
			t.Fatal("(a * b) * c == (a * c) * b")
		}
		square(a, zero)
		if !a.equal(zero) {
			t.Fatal("0^2 == 0")
		}
		square(a, one)
		if !a.equal(one) {
			t.Fatal("1^2 == 1")
		}
		_, _ = a.rand(rand.Reader)
		square(c_1, a)
		mul(c_2, a, a)
		if !c_1.equal(c_1) {
			t.Fatal("a^2 == a*a")
		}
	}
}

func TestFpExponentiation(t *testing.T) {
	for i := 0; i < fuz; i++ {
		a, _ := new(fe).rand(rand.Reader)
		u := new(fe)
		exp(u, a, big.NewInt(0))
		if !u.isOne() {
			t.Fatal("a^0 == 1")
		}
		exp(u, a, big.NewInt(1))
		if !u.equal(a) {
			t.Fatal("a^1 == a")
		}
		v := new(fe)
		mul(u, a, a)
		mul(u, u, u)
		mul(u, u, u)
		exp(v, a, big.NewInt(8))
		if !u.equal(v) {
			t.Fatal("((a^2)^2)^2 == a^8")
		}
		p := modulus.big()
		exp(u, a, p)
		if !u.equal(a) {
			t.Fatal("a^p == a")
		}
		exp(u, a, p.Sub(p, big.NewInt(1)))
		if !u.isOne() {
			t.Fatal("a^(p-1) == 1")
		}
	}
}

func TestFpInversion(t *testing.T) {
	for i := 0; i < fuz; i++ {
		u := new(fe)
		zero, one := new(fe).zero(), new(fe).one()
		inverse(u, zero)
		if !u.equal(zero) {
			t.Fatal("(0^-1) == 0)")
		}
		inverse(u, one)
		if !u.equal(one) {
			t.Fatal("(1^-1) == 1)")
		}
		a, _ := new(fe).rand(rand.Reader)
		inverse(u, a)
		mul(u, u, a)
		if !u.equal(one) {
			t.Fatal("(r*a) * r*(a^-1) == r)")
		}
		v := new(fe)
		p := modulus.big()
		exp(u, a, p.Sub(p, big.NewInt(2)))
		inverse(v, a)
		if !v.equal(u) {
			t.Fatal("a^(p-2) == a^-1")
		}
	}
}

func TestFpSquareRoot(t *testing.T) {
	r := new(fe)
	if sqrt(r, nonResidue1) {
		t.Fatal("non residue cannot have a sqrt")
	}
	for i := 0; i < fuz; i++ {
		a, _ := new(fe).rand(rand.Reader)
		aa, rr, r := &fe{}, &fe{}, &fe{}
		square(aa, a)
		if !sqrt(r, aa) {
			t.Fatal("bad sqrt 1")
		}
		square(rr, r)
		if !rr.equal(aa) {
			t.Fatal("bad sqrt 2")
		}
	}
}

func TestFpNonResidue(t *testing.T) {
	if !isQuadraticNonResidue(nonResidue1) {
		t.Fatal("element is quadratic non residue, 1")
	}
	if isQuadraticNonResidue(new(fe).one()) {
		t.Fatal("one is not quadratic non residue")
	}
	if !isQuadraticNonResidue(new(fe).zero()) {
		t.Fatal("should accept zero as quadratic non residue")
	}
	for i := 0; i < fuz; i++ {
		a, _ := new(fe).rand(rand.Reader)
		square(a, a)
		if isQuadraticNonResidue(new(fe).one()) {
			t.Fatal("element is not quadratic non residue")
		}
	}
	for i := 0; i < fuz; i++ {
		a, _ := new(fe).rand(rand.Reader)
		if !sqrt(new(fe), a) {
			if !isQuadraticNonResidue(a) {
				t.Fatal("element is quadratic non residue, 2", i)
			}
		} else {
			i -= 1
		}
	}

}

func TestFp2Serialization(t *testing.T) {
	field := newFp2()
	for i := 0; i < fuz; i++ {
		a, _ := new(fe2).rand(rand.Reader)
		b, err := field.fromBytes(field.toBytes(a))
		if err != nil {
			t.Fatal(err)
		}
		if !a.equal(b) {
			t.Fatal("bad serialization")
		}
	}
}

func TestFp2AdditionProperties(t *testing.T) {
	field := newFp2()
	for i := 0; i < fuz; i++ {
		zero := field.zero()
		a, _ := new(fe2).rand(rand.Reader)
		b, _ := new(fe2).rand(rand.Reader)
		c_1 := field.new()
		c_2 := field.new()
		field.add(c_1, a, zero)
		if !c_1.equal(a) {
			t.Fatal("a + 0 == a")
		}
		field.sub(c_1, a, zero)
		if !c_1.equal(a) {
			t.Fatal("a - 0 == a")
		}
		field.double(c_1, zero)
		if !c_1.equal(zero) {
			t.Fatal("2 * 0 == 0")
		}
		field.neg(c_1, zero)
		if !c_1.equal(zero) {
			t.Fatal("-0 == 0")
		}
		field.sub(c_1, zero, a)
		field.neg(c_2, a)
		if !c_1.equal(c_2) {
			t.Fatal("0-a == -a")
		}
		field.double(c_1, a)
		field.add(c_2, a, a)
		if !c_1.equal(c_2) {
			t.Fatal("2 * a == a + a")
		}
		field.add(c_1, a, b)
		field.add(c_2, b, a)
		if !c_1.equal(c_2) {
			t.Fatal("a + b = b + a")
		}
		field.sub(c_1, a, b)
		field.sub(c_2, b, a)
		field.neg(c_2, c_2)
		if !c_1.equal(c_2) {
			t.Fatal("a - b = - ( b - a )")
		}
		c_x, _ := new(fe2).rand(rand.Reader)
		field.add(c_1, a, b)
		field.add(c_1, c_1, c_x)
		field.add(c_2, a, c_x)
		field.add(c_2, c_2, b)
		if !c_1.equal(c_2) {
			t.Fatal("(a + b) + c == (a + c ) + b")
		}
		field.sub(c_1, a, b)
		field.sub(c_1, c_1, c_x)
		field.sub(c_2, a, c_x)
		field.sub(c_2, c_2, b)
		if !c_1.equal(c_2) {
			t.Fatal("(a - b) - c == (a - c ) -b")
		}
	}
}

func TestFp2AdditionPropertiesAssigned(t *testing.T) {
	field := newFp2()
	for i := 0; i < fuz; i++ {
		zero := new(fe2).zero()
		a, b := new(fe2), new(fe2)
		_, _ = a.rand(rand.Reader)
		b.set(a)
		field.addAssign(a, zero)
		if !a.equal(b) {
			t.Fatal("a + 0 == a")
		}
		field.subAssign(a, zero)
		if !a.equal(b) {
			t.Fatal("a - 0 == a")
		}
		a.set(zero)
		field.doubleAssign(a)
		if !a.equal(zero) {
			t.Fatal("2 * 0 == 0")
		}
		a.set(zero)
		field.subAssign(a, b)
		field.neg(b, b)
		if !a.equal(b) {
			t.Fatal("0-a == -a")
		}
		_, _ = a.rand(rand.Reader)
		b.set(a)
		field.doubleAssign(a)
		field.addAssign(b, b)
		if !a.equal(b) {
			t.Fatal("2 * a == a + a")
		}
		_, _ = a.rand(rand.Reader)
		_, _ = b.rand(rand.Reader)
		c_1, c_2 := new(fe2).set(a), new(fe2).set(b)
		field.addAssign(c_1, b)
		field.addAssign(c_2, a)
		if !c_1.equal(c_2) {
			t.Fatal("a + b = b + a")
		}
		_, _ = a.rand(rand.Reader)
		_, _ = b.rand(rand.Reader)
		c_1.set(a)
		c_2.set(b)
		field.subAssign(c_1, b)
		field.subAssign(c_2, a)
		field.neg(c_2, c_2)
		if !c_1.equal(c_2) {
			t.Fatal("a - b = - ( b - a )")
		}
		_, _ = a.rand(rand.Reader)
		_, _ = b.rand(rand.Reader)
		c, _ := new(fe2).rand(rand.Reader)
		a0 := new(fe2).set(a)
		field.addAssign(a, b)
		field.addAssign(a, c)
		field.addAssign(b, c)
		field.addAssign(b, a0)
		if !a.equal(b) {
			t.Fatal("(a + b) + c == (b + c) + a")
		}
		_, _ = a.rand(rand.Reader)
		_, _ = b.rand(rand.Reader)
		_, _ = c.rand(rand.Reader)
		a0.set(a)
		field.subAssign(a, b)
		field.subAssign(a, c)
		field.subAssign(a0, c)
		field.subAssign(a0, b)
		if !a.equal(a0) {
			t.Fatal("(a - b) - c == (a - c) -b")
		}
	}
}

func TestFp2LazyOperations(t *testing.T) {
	field := newFp2()
	for i := 0; i < fuz; i++ {
		a, _ := new(fe2).rand(rand.Reader)
		b, _ := new(fe2).rand(rand.Reader)
		c, _ := new(fe2).rand(rand.Reader)
		c0 := new(fe2)
		c1 := new(fe2)
		field.ladd(c0, a, b)
		field.add(c1, a, b)
		field.mulAssign(c0, c)
		field.mulAssign(c1, c)
		if !c0.equal(c1) {
			// l+ operator stands for lazy addition
			t.Fatal("(a + b) * c == (a l+ b) * c")
		}
		_, _ = a.rand(rand.Reader)
		b.set(a)
		field.ldouble(a, a)
		field.ladd(b, b, b)
		if !a.equal(b) {
			t.Fatal("2 l* a = a l+ a")
		}
	}
}

func TestFp2MultiplicationProperties(t *testing.T) {
	field := newFp2()
	for i := 0; i < fuz; i++ {
		a, _ := new(fe2).rand(rand.Reader)
		b, _ := new(fe2).rand(rand.Reader)
		zero := field.zero()
		one := field.one()
		c_1, c_2 := field.new(), field.new()
		field.mul(c_1, a, zero)
		if !c_1.equal(zero) {
			t.Fatal("a * 0 == 0")
		}
		field.mul(c_1, a, one)
		if !c_1.equal(a) {
			t.Fatal("a * 1 == a")
		}
		field.mul(c_1, a, b)
		field.mul(c_2, b, a)
		if !c_1.equal(c_2) {
			t.Fatal("a * b == b * a")
		}
		c_x, _ := new(fe2).rand(rand.Reader)
		field.mul(c_1, a, b)
		field.mul(c_1, c_1, c_x)
		field.mul(c_2, c_x, b)
		field.mul(c_2, c_2, a)
		if !c_1.equal(c_2) {
			t.Fatal("(a * b) * c == (a * c) * b")
		}
		field.square(a, zero)
		if !a.equal(zero) {
			t.Fatal("0^2 == 0")
		}
		field.square(a, one)
		if !a.equal(one) {
			t.Fatal("1^2 == 1")
		}
		_, _ = a.rand(rand.Reader)
		field.square(c_1, a)
		field.mul(c_2, a, a)
		if !c_2.equal(c_1) {
			t.Fatal("a^2 == a*a")
		}
	}
}

func TestFp2MultiplicationPropertiesAssigned(t *testing.T) {
	field := newFp2()
	for i := 0; i < fuz; i++ {
		a, _ := new(fe2).rand(rand.Reader)
		zero, one := new(fe2).zero(), new(fe2).one()
		field.mulAssign(a, zero)
		if !a.equal(zero) {
			t.Fatal("a * 0 == 0")
		}
		_, _ = a.rand(rand.Reader)
		a0 := new(fe2).set(a)
		field.mulAssign(a, one)
		if !a.equal(a0) {
			t.Fatal("a * 1 == a")
		}
		_, _ = a.rand(rand.Reader)
		b, _ := new(fe2).rand(rand.Reader)
		a0.set(a)
		field.mulAssign(a, b)
		field.mulAssign(b, a0)
		if !a.equal(b) {
			t.Fatal("a * b == b * a")
		}
		c, _ := new(fe2).rand(rand.Reader)
		a0.set(a)
		field.mulAssign(a, b)
		field.mulAssign(a, c)
		field.mulAssign(a0, c)
		field.mulAssign(a0, b)
		if !a.equal(a0) {
			t.Fatal("(a * b) * c == (a * c) * b")
		}
		a0.set(a)
		field.squareAssign(a)
		field.mulAssign(a0, a0)
		if !a.equal(a0) {
			t.Fatal("a^2 == a*a")
		}
	}
}

func TestFp2Exponentiation(t *testing.T) {
	field := newFp2()
	for i := 0; i < fuz; i++ {
		a, _ := new(fe2).rand(rand.Reader)
		u := field.new()
		field.exp(u, a, big.NewInt(0))
		if !u.equal(field.one()) {
			t.Fatal("a^0 == 1")
		}
		field.exp(u, a, big.NewInt(1))
		if !u.equal(a) {
			t.Fatal("a^1 == a")
		}
		v := field.new()
		field.mul(u, a, a)
		field.mul(u, u, u)
		field.mul(u, u, u)
		field.exp(v, a, big.NewInt(8))
		if !u.equal(v) {
			t.Fatal("((a^2)^2)^2 == a^8")
		}
	}
}

func TestFp2Inversion(t *testing.T) {
	field := newFp2()
	u := field.new()
	zero := field.zero()
	one := field.one()
	field.inverse(u, zero)
	if !u.equal(zero) {
		t.Fatal("(0 ^ -1) == 0)")
	}
	field.inverse(u, one)
	if !u.equal(one) {
		t.Fatal("(1 ^ -1) == 1)")
	}
	for i := 0; i < fuz; i++ {
		a, _ := new(fe2).rand(rand.Reader)
		field.inverse(u, a)
		field.mul(u, u, a)
		if !u.equal(one) {
			t.Fatal("(r * a) * r * (a ^ -1) == r)")
		}
	}
}

func TestFp2SquareRoot(t *testing.T) {
	field := newFp2()
	for z := 0; z < 1000; z++ {
		zi := new(fe)
		sub(zi, &modulus, &fe{uint64(z * z)})
		// r = (-z*z, 0)
		r := &fe2{*zi, fe{0}}
		toMont(&r[0], &r[0])
		toMont(&r[1], &r[1])
		c := field.new()
		// sqrt((-z*z, 0)) = (0, z)
		if !field.sqrt(c, r) {
			t.Fatal("z*z does have a square root")
		}
		e := &fe2{fe{uint64(0)}, fe{uint64(z)}}
		toMont(&e[0], &e[0])
		toMont(&e[1], &e[1])
		field.square(e, e)
		field.square(c, c)
		if !e.equal(c) {
			t.Fatal("square root failed")
		}
	}
	if field.sqrt(field.new(), nonResidue2) {
		t.Fatal("non residue cannot have a sqrt")
	}
	for i := 0; i < fuz; i++ {
		a, _ := new(fe2).rand(rand.Reader)
		aa, rr, r := field.new(), field.new(), field.new()
		field.square(aa, a)
		if !field.sqrt(r, aa) {
			t.Fatal("bad sqrt 1")
		}
		field.square(rr, r)
		if !rr.equal(aa) {
			t.Fatal("bad sqrt 2")
		}
	}
}

func TestFp2NonResidue(t *testing.T) {
	field := newFp2()
	if !field.isQuadraticNonResidue(nonResidue2) {
		t.Fatal("element is quadratic non residue, 1")
	}
	if field.isQuadraticNonResidue(new(fe2).one()) {
		t.Fatal("one is not quadratic non residue")
	}
	if !field.isQuadraticNonResidue(new(fe2).zero()) {
		t.Fatal("should accept zero as quadratic non residue")
	}
	for i := 0; i < fuz; i++ {
		a, _ := new(fe2).rand(rand.Reader)
		field.squareAssign(a)
		if field.isQuadraticNonResidue(new(fe2).one()) {
			t.Fatal("element is not quadratic non residue")
		}
	}
	for i := 0; i < fuz; i++ {
		a, _ := new(fe2).rand(rand.Reader)
		if !field.sqrt(new(fe2), a) {
			if !field.isQuadraticNonResidue(a) {
				t.Fatal("element is quadratic non residue, 2", i)
			}
		} else {
			i -= 1
		}
	}
}

func TestFp6Serialization(t *testing.T) {
	field := newFp6(nil)
	for i := 0; i < fuz; i++ {
		a, _ := new(fe6).rand(rand.Reader)
		b, err := field.fromBytes(field.toBytes(a))
		if err != nil {
			t.Fatal(err)
		}
		if !a.equal(b) {
			t.Fatal("bad serialization")
		}
	}
}

func TestFp6AdditionProperties(t *testing.T) {
	field := newFp6(nil)
	for i := 0; i < fuz; i++ {
		zero := field.zero()
		a, _ := new(fe6).rand(rand.Reader)
		b, _ := new(fe6).rand(rand.Reader)
		c_1 := field.new()
		c_2 := field.new()
		field.add(c_1, a, zero)
		if !c_1.equal(a) {
			t.Fatal("a + 0 == a")
		}
		field.sub(c_1, a, zero)
		if !c_1.equal(a) {
			t.Fatal("a - 0 == a")
		}
		field.double(c_1, zero)
		if !c_1.equal(zero) {
			t.Fatal("2 * 0 == 0")
		}
		field.neg(c_1, zero)
		if !c_1.equal(zero) {
			t.Fatal("-0 == 0")
		}
		field.sub(c_1, zero, a)
		field.neg(c_2, a)
		if !c_1.equal(c_2) {
			t.Fatal("0-a == -a")
		}
		field.double(c_1, a)
		field.add(c_2, a, a)
		if !c_1.equal(c_2) {
			t.Fatal("2 * a == a + a")
		}
		field.add(c_1, a, b)
		field.add(c_2, b, a)
		if !c_1.equal(c_2) {
			t.Fatal("a + b = b + a")
		}
		field.sub(c_1, a, b)
		field.sub(c_2, b, a)
		field.neg(c_2, c_2)
		if !c_1.equal(c_2) {
			t.Fatal("a - b = - ( b - a )")
		}
		c_x, _ := new(fe6).rand(rand.Reader)
		field.add(c_1, a, b)
		field.add(c_1, c_1, c_x)
		field.add(c_2, a, c_x)
		field.add(c_2, c_2, b)
		if !c_1.equal(c_2) {
			t.Fatal("(a + b) + c == (a + c ) + b")
		}
		field.sub(c_1, a, b)
		field.sub(c_1, c_1, c_x)
		field.sub(c_2, a, c_x)
		field.sub(c_2, c_2, b)
		if !c_1.equal(c_2) {
			t.Fatal("(a - b) - c == (a - c ) -b")
		}
	}
}

func TestFp6AdditionPropertiesAssigned(t *testing.T) {
	field := newFp6(nil)
	for i := 0; i < fuz; i++ {
		zero := new(fe6).zero()
		a, b := new(fe6), new(fe6)
		_, _ = a.rand(rand.Reader)
		b.set(a)
		field.addAssign(a, zero)
		if !a.equal(b) {
			t.Fatal("a + 0 == a")
		}
		field.subAssign(a, zero)
		if !a.equal(b) {
			t.Fatal("a - 0 == a")
		}
		a.set(zero)
		field.doubleAssign(a)
		if !a.equal(zero) {
			t.Fatal("2 * 0 == 0")
		}
		a.set(zero)
		field.subAssign(a, b)
		field.neg(b, b)
		if !a.equal(b) {
			t.Fatal("0-a == -a")
		}
		_, _ = a.rand(rand.Reader)
		b.set(a)
		field.doubleAssign(a)
		field.addAssign(b, b)
		if !a.equal(b) {
			t.Fatal("2 * a == a + a")
		}
		_, _ = a.rand(rand.Reader)
		_, _ = b.rand(rand.Reader)
		c_1, c_2 := new(fe6).set(a), new(fe6).set(b)
		field.addAssign(c_1, b)
		field.addAssign(c_2, a)
		if !c_1.equal(c_2) {
			t.Fatal("a + b = b + a")
		}
		_, _ = a.rand(rand.Reader)
		_, _ = b.rand(rand.Reader)
		c_1.set(a)
		c_2.set(b)
		field.subAssign(c_1, b)
		field.subAssign(c_2, a)
		field.neg(c_2, c_2)
		if !c_1.equal(c_2) {
			t.Fatal("a - b = - ( b - a )")
		}
		_, _ = a.rand(rand.Reader)
		_, _ = b.rand(rand.Reader)
		c, _ := new(fe6).rand(rand.Reader)
		a0 := new(fe6).set(a)
		field.addAssign(a, b)
		field.addAssign(a, c)
		field.addAssign(b, c)
		field.addAssign(b, a0)
		if !a.equal(b) {
			t.Fatal("(a + b) + c == (b + c) + a")
		}
		_, _ = a.rand(rand.Reader)
		_, _ = b.rand(rand.Reader)
		_, _ = c.rand(rand.Reader)
		a0.set(a)
		field.subAssign(a, b)
		field.subAssign(a, c)
		field.subAssign(a0, c)
		field.subAssign(a0, b)
		if !a.equal(a0) {
			t.Fatal("(a - b) - c == (a - c) -b")
		}
	}
}

func TestFp6SparseMultiplication(t *testing.T) {
	fp6 := newFp6(nil)
	var a, b, u *fe6
	for j := 0; j < fuz; j++ {
		a, _ = new(fe6).rand(rand.Reader)
		b, _ = new(fe6).rand(rand.Reader)
		u, _ = new(fe6).rand(rand.Reader)
		b[2].zero()
		fp6.mul(u, a, b)
		fp6.mulBy01(a, a, &b[0], &b[1])
		if !a.equal(u) {
			t.Fatal("bad mul by 01")
		}
	}
	for j := 0; j < fuz; j++ {
		a, _ = new(fe6).rand(rand.Reader)
		b, _ = new(fe6).rand(rand.Reader)
		u, _ = new(fe6).rand(rand.Reader)
		b[2].zero()
		b[0].zero()
		fp6.mul(u, a, b)
		fp6.mulBy1(a, a, &b[1])
		if !a.equal(u) {
			t.Fatal("bad mul by 1")
		}
	}
}

func TestFp6MultiplicationProperties(t *testing.T) {
	field := newFp6(nil)
	for i := 0; i < fuz; i++ {
		a, _ := new(fe6).rand(rand.Reader)
		b, _ := new(fe6).rand(rand.Reader)
		zero := field.zero()
		one := field.one()
		c_1, c_2 := field.new(), field.new()
		field.mul(c_1, a, zero)
		if !c_1.equal(zero) {
			t.Fatal("a * 0 == 0")
		}
		field.mul(c_1, a, one)
		if !c_1.equal(a) {
			t.Fatal("a * 1 == a")
		}
		field.mul(c_1, a, b)
		field.mul(c_2, b, a)
		if !c_1.equal(c_2) {
			t.Fatal("a * b == b * a")
		}
		c_x, _ := new(fe6).rand(rand.Reader)
		field.mul(c_1, a, b)
		field.mul(c_1, c_1, c_x)
		field.mul(c_2, c_x, b)
		field.mul(c_2, c_2, a)
		if !c_1.equal(c_2) {
			t.Fatal("(a * b) * c == (a * c) * b")
		}
		field.square(a, zero)
		if !a.equal(zero) {
			t.Fatal("0^2 == 0")
		}
		field.square(a, one)
		if !a.equal(one) {
			t.Fatal("1^2 == 1")
		}
		_, _ = a.rand(rand.Reader)
		field.square(c_1, a)
		field.mul(c_2, a, a)
		if !c_2.equal(c_1) {
			t.Fatal("a^2 == a*a")
		}
	}
}

func TestFp6MultiplicationPropertiesAssigned(t *testing.T) {
	field := newFp6(nil)
	for i := 0; i < fuz; i++ {
		a, _ := new(fe6).rand(rand.Reader)
		zero, one := new(fe6).zero(), new(fe6).one()
		field.mulAssign(a, zero)
		if !a.equal(zero) {
			t.Fatal("a * 0 == 0")
		}
		_, _ = a.rand(rand.Reader)
		a0 := new(fe6).set(a)
		field.mulAssign(a, one)
		if !a.equal(a0) {
			t.Fatal("a * 1 == a")
		}
		_, _ = a.rand(rand.Reader)
		b, _ := new(fe6).rand(rand.Reader)
		a0.set(a)
		field.mulAssign(a, b)
		field.mulAssign(b, a0)
		if !a.equal(b) {
			t.Fatal("a * b == b * a")
		}
		c, _ := new(fe6).rand(rand.Reader)
		a0.set(a)
		field.mulAssign(a, b)
		field.mulAssign(a, c)
		field.mulAssign(a0, c)
		field.mulAssign(a0, b)
		if !a.equal(a0) {
			t.Fatal("(a * b) * c == (a * c) * b")
		}
	}
}

func TestFp6Exponentiation(t *testing.T) {
	field := newFp6(nil)
	for i := 0; i < fuz; i++ {
		a, _ := new(fe6).rand(rand.Reader)
		u := field.new()
		field.exp(u, a, big.NewInt(0))
		if !u.equal(field.one()) {
			t.Fatal("a^0 == 1")
		}
		field.exp(u, a, big.NewInt(1))
		if !u.equal(a) {
			t.Fatal("a^1 == a")
		}
		v := field.new()
		field.mul(u, a, a)
		field.mul(u, u, u)
		field.mul(u, u, u)
		field.exp(v, a, big.NewInt(8))
		if !u.equal(v) {
			t.Fatal("((a^2)^2)^2 == a^8")
		}
	}
}

func TestFp6Inversion(t *testing.T) {
	field := newFp6(nil)
	for i := 0; i < fuz; i++ {
		u := field.new()
		zero := field.zero()
		one := field.one()
		field.inverse(u, zero)
		if !u.equal(zero) {
			t.Fatal("(0^-1) == 0)")
		}
		field.inverse(u, one)
		if !u.equal(one) {
			t.Fatal("(1^-1) == 1)")
		}
		a, _ := new(fe6).rand(rand.Reader)
		field.inverse(u, a)
		field.mul(u, u, a)
		if !u.equal(one) {
			t.Fatal("(r*a) * r*(a^-1) == r)")
		}
	}
}

func TestFp12Serialization(t *testing.T) {
	field := newFp12(nil)
	for i := 0; i < fuz; i++ {
		a, _ := new(fe12).rand(rand.Reader)
		b, err := field.fromBytes(field.toBytes(a))
		if err != nil {
			t.Fatal(err)
		}
		if !a.equal(b) {
			t.Fatal("bad serialization")
		}
	}
}

func TestFp12AdditionProperties(t *testing.T) {
	field := newFp12(nil)
	for i := 0; i < fuz; i++ {
		zero := field.zero()
		a, _ := new(fe12).rand(rand.Reader)
		b, _ := new(fe12).rand(rand.Reader)
		c_1 := field.new()
		c_2 := field.new()
		field.add(c_1, a, zero)
		if !c_1.equal(a) {
			t.Fatal("a + 0 == a")
		}
		field.sub(c_1, a, zero)
		if !c_1.equal(a) {
			t.Fatal("a - 0 == a")
		}
		field.double(c_1, zero)
		if !c_1.equal(zero) {
			t.Fatal("2 * 0 == 0")
		}
		field.neg(c_1, zero)
		if !c_1.equal(zero) {
			t.Fatal("-0 == 0")
		}
		field.sub(c_1, zero, a)
		field.neg(c_2, a)
		if !c_1.equal(c_2) {
			t.Fatal("0-a == -a")
		}
		field.double(c_1, a)
		field.add(c_2, a, a)
		if !c_1.equal(c_2) {
			t.Fatal("2 * a == a + a")
		}
		field.add(c_1, a, b)
		field.add(c_2, b, a)
		if !c_1.equal(c_2) {
			t.Fatal("a + b = b + a")
		}
		field.sub(c_1, a, b)
		field.sub(c_2, b, a)
		field.neg(c_2, c_2)
		if !c_1.equal(c_2) {
			t.Fatal("a - b = - ( b - a )")
		}
		c_x, _ := new(fe12).rand(rand.Reader)
		field.add(c_1, a, b)
		field.add(c_1, c_1, c_x)
		field.add(c_2, a, c_x)
		field.add(c_2, c_2, b)
		if !c_1.equal(c_2) {
			t.Fatal("(a + b) + c == (a + c ) + b")
		}
		field.sub(c_1, a, b)
		field.sub(c_1, c_1, c_x)
		field.sub(c_2, a, c_x)
		field.sub(c_2, c_2, b)
		if !c_1.equal(c_2) {
			t.Fatal("(a - b) - c == (a - c ) -b")
		}
	}
}

func TestFp12MultiplicationProperties(t *testing.T) {
	field := newFp12(nil)
	for i := 0; i < fuz; i++ {
		a, _ := new(fe12).rand(rand.Reader)
		b, _ := new(fe12).rand(rand.Reader)
		zero := field.zero()
		one := field.one()
		c_1, c_2 := field.new(), field.new()
		field.mul(c_1, a, zero)
		if !c_1.equal(zero) {
			t.Fatal("a * 0 == 0")
		}
		field.mul(c_1, a, one)
		if !c_1.equal(a) {
			t.Fatal("a * 1 == a")
		}
		field.mul(c_1, a, b)
		field.mul(c_2, b, a)
		if !c_1.equal(c_2) {
			t.Fatal("a * b == b * a")
		}
		c_x, _ := new(fe12).rand(rand.Reader)
		field.mul(c_1, a, b)
		field.mul(c_1, c_1, c_x)
		field.mul(c_2, c_x, b)
		field.mul(c_2, c_2, a)
		if !c_1.equal(c_2) {
			t.Fatal("(a * b) * c == (a * c) * b")
		}
		field.square(a, zero)
		if !a.equal(zero) {
			t.Fatal("0^2 == 0")
		}
		field.square(a, one)
		if !a.equal(one) {
			t.Fatal("1^2 == 1")
		}
		_, _ = a.rand(rand.Reader)
		field.square(c_1, a)
		field.mul(c_2, a, a)
		if !c_2.equal(c_1) {
			t.Fatal("a^2 == a*a")
		}
	}
}

func TestFp12MultiplicationPropertiesAssigned(t *testing.T) {
	field := newFp12(nil)
	for i := 0; i < fuz; i++ {
		a, _ := new(fe12).rand(rand.Reader)
		zero, one := new(fe12).zero(), new(fe12).one()
		field.mulAssign(a, zero)
		if !a.equal(zero) {
			t.Fatal("a * 0 == 0")
		}
		_, _ = a.rand(rand.Reader)
		a0 := new(fe12).set(a)
		field.mulAssign(a, one)
		if !a.equal(a0) {
			t.Fatal("a * 1 == a")
		}
		_, _ = a.rand(rand.Reader)
		b, _ := new(fe12).rand(rand.Reader)
		a0.set(a)
		field.mulAssign(a, b)
		field.mulAssign(b, a0)
		if !a.equal(b) {
			t.Fatal("a * b == b * a")
		}
		c, _ := new(fe12).rand(rand.Reader)
		a0.set(a)
		field.mulAssign(a, b)
		field.mulAssign(a, c)
		field.mulAssign(a0, c)
		field.mulAssign(a0, b)
		if !a.equal(a0) {
			t.Fatal("(a * b) * c == (a * c) * b")
		}
	}
}

func TestFp12SparseMultiplication(t *testing.T) {
	fp12 := newFp12(nil)
	var a, b, u *fe12
	for j := 0; j < fuz; j++ {
		a, _ = new(fe12).rand(rand.Reader)
		b, _ = new(fe12).rand(rand.Reader)
		u, _ = new(fe12).rand(rand.Reader)
		b[0][2].zero()
		b[1][0].zero()
		b[1][2].zero()
		fp12.mul(u, a, b)
		fp12.mulBy014Assign(a, &b[0][0], &b[0][1], &b[1][1])
		if !a.equal(u) {
			t.Fatal("bad mul by 01")
		}
	}
}

func TestFp12Exponentiation(t *testing.T) {
	field := newFp12(nil)
	for i := 0; i < fuz; i++ {
		a, _ := new(fe12).rand(rand.Reader)
		u := field.new()
		field.exp(u, a, big.NewInt(0))
		if !u.equal(field.one()) {
			t.Fatal("a^0 == 1")
		}
		field.exp(u, a, big.NewInt(1))
		if !u.equal(a) {
			t.Fatal("a^1 == a")
		}
		v := field.new()
		field.mul(u, a, a)
		field.mul(u, u, u)
		field.mul(u, u, u)
		field.exp(v, a, big.NewInt(8))
		if !u.equal(v) {
			t.Fatal("((a^2)^2)^2 == a^8")
		}
	}
}

func TestFp12Inversion(t *testing.T) {
	field := newFp12(nil)
	for i := 0; i < fuz; i++ {
		u := field.new()
		zero := field.zero()
		one := field.one()
		field.inverse(u, zero)
		if !u.equal(zero) {
			t.Fatal("(0^-1) == 0)")
		}
		field.inverse(u, one)
		if !u.equal(one) {
			t.Fatal("(1^-1) == 1)")
		}
		a, _ := new(fe12).rand(rand.Reader)
		field.inverse(u, a)
		field.mul(u, u, a)
		if !u.equal(one) {
			t.Fatal("(r*a) * r*(a^-1) == r)")
		}
	}
}

func BenchmarkMultiplication(t *testing.B) {
	a, _ := new(fe).rand(rand.Reader)
	b, _ := new(fe).rand(rand.Reader)
	c, _ := new(fe).rand(rand.Reader)
	t.ResetTimer()
	for i := 0; i < t.N; i++ {
		mul(c, a, b)
	}
}

func BenchmarkInverse(t *testing.B) {
	a, _ := new(fe).rand(rand.Reader)
	b, _ := new(fe).rand(rand.Reader)
	t.ResetTimer()
	for i := 0; i < t.N; i++ {
		inverse(a, b)
	}
}

func padBytes(in []byte, size int) []byte {
	out := make([]byte, size)
	if len(in) > size {
		panic("bad input for padding")
	}
	copy(out[size-len(in):], in)
	return out
}
