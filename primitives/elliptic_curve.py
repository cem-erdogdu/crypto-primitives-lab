"""
Elliptic curve point arithmetic for secp256k1.

This module provides a Point class that represents points on the secp256k1 curve,
which is defined by the equation:

    y^2 = x^3 + ax + b  (mod p)

For secp256k1: a = 0, b = 7, and p is the large prime defined in constants.py.

The curve forms a cyclic group under the "point addition" operation. This group
structure is the foundation of elliptic curve cryptography (ECC), enabling
operations like public key derivation where a public key is simply a private
key (scalar) multiplied by the generator point G.

Key concepts:
- A "point" is a pair (x, y) satisfying the curve equation, or the special
  "point at infinity" which serves as the identity element (like 0 in addition).
- Adding a point to itself is called "point doubling."
- Repeated addition of a point k times is called "scalar multiplication" and
  is written as k * P. This is efficient to compute using the double-and-add
  algorithm.
"""

from primitives.constants import P, A, B, N, GX, GY
from primitives.field_math import mod_inverse


class Point:
    """
    Represents a point on the secp256k1 elliptic curve.

    A point is either:
    - A finite point (x, y) that satisfies y^2 ≡ x^3 + ax + b (mod p), or
    - The special "point at infinity," denoted here as the identity element.

    The point at infinity is the additive identity: for any point P,
    P + infinity = P. It arises naturally when adding two points whose
    connecting line is vertical (i.e., when x1 == x2 but y1 != y2),
    which geometrically means the line "goes off to infinity."

    Attributes:
        x: The x-coordinate (or None if this is the point at infinity).
        y: The y-coordinate (or None if this is the point at infinity).
        is_infinity: True if this is the point at infinity, False otherwise.
    """

    def __init__(self, x: int | None = None, y: int | None = None):
        """
        Create a new point on the curve.

        If both x and y are None, this creates the point at infinity.
        Otherwise, x and y must satisfy the curve equation y^2 = x^3 + ax + b (mod p).

        Args:
            x: The x-coordinate of the point, or None for infinity.
            y: The y-coordinate of the point, or None for infinity.

        Raises:
            ValueError: If the given (x, y) does not lie on the curve.
        """
        if x is None and y is None:
            # This is the point at infinity — the identity element of the group.
            # Geometrically, it represents the "point" where all vertical lines meet.
            self.x = None
            self.y = None
            self.is_infinity = True
        else:
            # Verify that the point actually lies on the curve.
            # The curve equation is: y^2 ≡ x^3 + ax + b (mod p)
            # We compute both sides and check they are equal modulo p.
            lhs = (y * y) % P  # Left-hand side: y^2 mod p
            rhs = (pow(x, 3, P) + A * x + B) % P  # Right-hand side: x^3 + ax + b mod p

            if lhs != rhs:
                raise ValueError(
                    f"Point ({x}, {y}) does not lie on the secp256k1 curve"
                )

            self.x = x % P
            self.y = y % P
            self.is_infinity = False

    @classmethod
    def generator(cls) -> "Point":
        """
        Return the generator point G for secp256k1.

        G is a publicly known, fixed point on the curve. All public keys in
        Bitcoin and other systems are computed as k * G where k is the private
        key (a scalar in the range [1, N-1]).

        Returns:
            The generator point G = (GX, GY).
        """
        return cls(GX, GY)

    @classmethod
    def infinity(cls) -> "Point":
        """
        Return the point at infinity.

        This is the identity element of the elliptic curve group. Adding it
        to any point P yields P unchanged: P + infinity = P.

        Returns:
            The point at infinity.
        """
        return cls(None, None)

    def __eq__(self, other: object) -> bool:
        """
        Check equality between two points.

        Two finite points are equal if their coordinates match.
        The point at infinity is only equal to itself.
        """
        if not isinstance(other, Point):
            return False
        if self.is_infinity and other.is_infinity:
            return True
        if self.is_infinity or other.is_infinity:
            return False
        return self.x == other.x and self.y == other.y

    def __repr__(self) -> str:
        """Return a human-readable string representation of the point."""
        if self.is_infinity:
            return "Point(infinity)"
        return f"Point({hex(self.x)}, {hex(self.y)})"

    def __add__(self, other: "Point") -> "Point":
        """
        Add two points on the elliptic curve (group operation).

        This implements the standard point addition law for elliptic curves.
        The underlying mathematics depends on whether we are adding two
        distinct points or doubling a point.

        Case 1: Adding two distinct points P = (x1, y1) and Q = (x2, y2) where x1 != x2

            Geometrically: draw a line through P and Q. This line intersects the
            curve at exactly one more point R'. The sum P + Q is defined as the
            reflection of R' across the x-axis.

            Algebraically:
                λ = (y2 - y1) / (x2 - x1)   (mod p)      <-- slope of the line
                x3 = λ² - x1 - x2           (mod p)
                y3 = λ(x1 - x3) - y1        (mod p)

            The division is performed using modular inverse (via Fermat's little
            theorem), since we work in a finite field where "division" means
            multiplication by the modular inverse.

        Case 2: Doubling a point P = (x1, y1) — i.e., adding P to itself

            Geometrically: draw the tangent line to the curve at P. This line
            intersects the curve at exactly one more point R'. The result 2P
            is the reflection of R' across the x-axis.

            Algebraically (with a=0 for secp256k1):
                λ = (3x1² + a) / (2y1)      (mod p)      <-- slope of the tangent
                x3 = λ² - 2x1               (mod p)
                y3 = λ(x1 - x3) - y1        (mod p)

        Special case: Point at infinity

            - P + infinity = P  (identity property)
            - If x1 == x2 but y1 != y2, the line is vertical and intersects the
              curve only at P and Q; the "third point" is at infinity.
              So P + Q = infinity in this case.

        Args:
            other: The point to add to this point.

        Returns:
            The sum of this point and other.
        """
        # Handle the point at infinity: it is the identity element.
        # Adding infinity to any point P just returns P.
        if self.is_infinity:
            return other
        if other.is_infinity:
            return self

        x1, y1 = self.x, self.y
        x2, y2 = other.x, other.y

        # Special case: the two points have the same x-coordinate but different y-coordinates.
        # Geometrically this means the line through them is vertical — it "goes to infinity."
        # The result is therefore the point at infinity.
        if x1 == x2 and y1 != y2:
            return Point.infinity()

        # Determine the slope λ of the line (or tangent, if doubling).
        if x1 == x2 and y1 == y2:
            # -------------------------------------------------------
            # POINT DOUBLING: P + P = 2P
            # -------------------------------------------------------
            # We are adding a point to itself, so we need the tangent slope.
            #
            # For a curve y^2 = x^3 + ax + b, implicit differentiation gives:
            #
            #     dy/dx = (3x^2 + a) / (2y)
            #
            # This is the slope of the tangent at point (x, y).
            #
            # In secp256k1, a = 0, so this simplifies to:
            #
            #     λ = 3x1² / (2y1)   (mod p)
            #
            # We compute this using modular arithmetic:
            #   - Numerator: 3 * x1^2  (mod p)
            #   - Denominator: 2 * y1  (mod p), which requires modular inverse
            # -------------------------------------------------------

            if y1 == 0:
                # The tangent is vertical (y-coordinate is 0), so the result
                # is the point at infinity. This happens when P is a point
                # whose order divides 2 in the group.
                return Point.infinity()

            # Compute λ = (3 * x1^2 + a) / (2 * y1) mod p
            # For secp256k1, a = 0, but we keep the general form.
            numerator = (3 * x1 * x1 + A) % P
            denominator = (2 * y1) % P
            lam = (numerator * mod_inverse(denominator, P)) % P
        else:
            # -------------------------------------------------------
            # POINT ADDITION: P + Q where P != Q
            # -------------------------------------------------------
            # We draw a line through the two distinct points P and Q.
            # The slope of this line is:
            #
            #     λ = (y2 - y1) / (x2 - x1)   (mod p)
            #
            # Again, division in the finite field is multiplication by
            # the modular inverse.
            # -------------------------------------------------------

            # Compute λ = (y2 - y1) / (x2 - x1) mod p
            numerator = (y2 - y1) % P
            denominator = (x2 - x1) % P
            lam = (numerator * mod_inverse(denominator, P)) % P

        # -------------------------------------------------------
        # COMPUTE THE RESULTING POINT
        # -------------------------------------------------------
        # Once we have the slope λ, the new point (x3, y3) is given by:
        #
        #     x3 = λ² - x1 - x2   (mod p)
        #     y3 = λ(x1 - x3) - y1  (mod p)
        #
        # Geometrically, (x3, -y3) is where the line intersects the curve
        # a third time, and we then reflect across the x-axis to get (x3, y3).
        # -------------------------------------------------------

        x3 = (lam * lam - x1 - x2) % P
        y3 = (lam * (x1 - x3) - y1) % P

        return Point(x3, y3)

    def __mul__(self, scalar: int) -> "Point":
        """
        Multiply this point by a scalar (scalar multiplication).

        This computes k * P, which is P added to itself k times:
            k * P = P + P + P + ... + P  (k times)

        While this sounds slow for large k, it can be done efficiently using
        the "double-and-add" algorithm, which is analogous to exponentiation
        by squaring. The number of operations is O(log k) instead of O(k).

        The underlying mathematics:
        --------------------------
        Scalar multiplication is the core operation in elliptic curve cryptography.
        Given a private key k (a large integer) and the generator point G,
        the public key is simply:

            PublicKey = k * G

        This is easy to compute in one direction (given k and G, find k*G),
        but believed to be computationally infeasible in the reverse direction
        (given k*G and G, find k). This one-way property is called the
        "Elliptic Curve Discrete Logarithm Problem" (ECDLP).

        Algorithm (double-and-add, binary method, left-to-right):
        ---------------------------------------------------------
        We process the binary representation of k from most significant bit
        to least significant bit:

            result = infinity
            for each bit b in k (from MSB to LSB):
                result = 2 * result        # always double
                if b == 1:
                    result = result + P    # add P only when the bit is set

        This works because any integer k can be written in binary as:
            k = 2^(n-1)*b_{n-1} + 2^(n-2)*b_{n-2} + ... + 2*b_1 + b_0

        and we can rewrite k * P as:
            k * P = 2*(2*(...2*(b_{n-1}*P) + b_{n-2}*P...) + b_1*P) + b_0*P

        which is exactly what the loop above computes.

        Args:
            scalar: The integer k to multiply by (the "private key" in ECC).

        Returns:
            The point k * P.
        """
        # Handle the point at infinity: multiplying it by anything still gives infinity.
        if self.is_infinity:
            return Point.infinity()

        # Handle scalar = 0: 0 * P = infinity (by convention / identity property).
        if scalar == 0:
            return Point.infinity()

        # Reduce the scalar modulo N (the order of the curve) since k * P = (k mod N) * P.
        # This is because N * P = infinity, so the group has order N.
        k = scalar % N

        if k == 0:
            return Point.infinity()

        # -------------------------------------------------------
        # DOUBLE-AND-ADD ALGORITHM (binary exponentiation analog)
        # -------------------------------------------------------
        # We iterate through the bits of k from most significant to least significant.
        # At each step:
        #   - We always double the current result (this handles the "2*" factor).
        #   - If the current bit is 1, we also add P (this handles the "+1" when bit is set).
        #
        # Starting from result = infinity and processing each bit builds up k * P.
        # -------------------------------------------------------

        result = Point.infinity()  # Start with the identity element
        addend = self  # This will be 2^i * P as we go

        # Process bits from MSB to LSB
        # We need to know how many bits k has. We can use bit_length().
        for i in range(k.bit_length() - 1, -1, -1):
            # Always double: this corresponds to multiplying by 2 in the exponent.
            result = result + result  # 2 * result

            # Check if bit i of k is set (1).
            # k >> i shifts k right by i bits, so the LSB is now bit i of the original k.
            if (k >> i) & 1:
                # Add P (well, 2^i * P) when this bit contributes to k.
                result = result + addend

        return result

    def __rmul__(self, scalar: int) -> "Point":
        """
        Support scalar * point syntax (e.g., 2 * G).

        Python calls __rmul__ when the left operand doesn't support the operation.
        By delegating to __mul__, we allow both point * scalar and scalar * point.
        """
        return self.__mul__(scalar)

    def is_on_curve(self) -> bool:
        """
        Verify that this point satisfies the curve equation.

        For a finite point (x, y), checks that y^2 ≡ x^3 + ax + b (mod p).
        The point at infinity is always considered valid.

        Returns:
            True if the point is on the curve (or is infinity), False otherwise.
        """
        if self.is_infinity:
            return True

        lhs = (self.y * self.y) % P
        rhs = (pow(self.x, 3, P) + A * self.x + B) % P
        return lhs == rhs
