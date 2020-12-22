// Eric Landquist
// Virginia Tech

// November 7, 1998

import java.math.BigInteger;
import java.io.*;
import java.util.Random;

// This class will find two primes, p and q, and a generator, g, of p such that g^q = 1 (modp).
// This will be used in the ECash program to produce such numbers needed for challenging the validity of a coin.

class QPGGen {

public static final BigInteger modulus = new BigInteger("67121633100854333760823216471326079676039838960980375144787957703044941147081296059123997261399910613390603844272962446505560297966424631213047304914323469022909185522090033023879429769168557156271032061067995076629568463341021245792743115819466961853594162377852172085064974026021473181363138895145026648893");

	public QPGGen(){
	}
	
	public static void main(String args[]) {
		
		// We first want to find a prime that is of the form 2nq+1, where n is an integer and q is prime.
		// such that 2npq+1 is 128 bytes long.
		BigInteger[] primes = getPrimes();
		try {
			PrintWriter primeFile = new PrintWriter(new FileWriter("primestuff.txt"));
			primeFile.println(primes[0].toString());
			primeFile.println(primes[1].toString());
			primeFile.println(primes[2].toString());
			primeFile.close();
		} catch (IOException ioe) {
			System.out.println("D'OH!");
		}
		
	} // end main()

// Method:	getPrimes()
// Purpose:	To generate a 128 byte prime number of the form p= 2nq+1, where n is an integer, 
//				and p, q are primes.

	static BigInteger[] getPrimes () {
	
		// Random 128 byte primes.
		BigInteger q = new BigInteger (1017, 50, new Random());
		BigInteger two = new BigInteger("2");
		BigInteger one = new BigInteger("1");
		BigInteger n = one;
		BigInteger g = two;
		
		BigInteger primetemp = two.multiply(q);
		BigInteger prime = primetemp.add(one);
		
		while(true) {
			for (int i=0; ; i++) {
				if (prime.toByteArray().length == 128 && prime.compareTo(modulus) == -1) {
				
					if (prime.isProbablePrime(50)) {
						try {
							PrintWriter primeFile = new PrintWriter(new FileWriter("primes.txt"));
							primeFile.println(prime.toString());
							primeFile.println(q.toString());
							primeFile.println(n.toString());
							primeFile.close();
						} catch (IOException ioe) {
							System.out.println("D'OH!");
						}
						System.out.println(n.toString());
						for (int j=0; j<150; j++) {
							if (g.modPow(q, prime).equals(one)){
								BigInteger[] primes = new BigInteger[3];
								primes[0] = prime;
								primes[1] = q;
								primes[2] = g;
								return primes;
							}
							else {
								g= g.add(one);
							}
						} // end for loop
					} // end if 
					else {
						n = n.add(one);
						prime = primetemp.multiply(n).add(one);
					} // end else
				} // end if
				else if (prime.toByteArray().length < 128) {
					n = n.add(one);
					prime = primetemp.multiply(n).add(one);
				}
				else {
					break;
				}
			}
			q = new BigInteger (1017, 50, new Random());
			n = one;
			primetemp = two.multiply(q);
			prime = primetemp.add(one);
		}
		
	} // end getPrimes()


// Method: 	primRoot()
// Purpose: To find a primitive root of a given prime.
// Parameter: primes -- the primes.
//			  factors -- the factors.

	public static BigInteger primRoot(BigInteger[] primes, BigInteger[] factors) {
		BigInteger g = new BigInteger("2");
		BigInteger one = new BigInteger("1");
		BigInteger p1 = primes[0].subtract(one);
		
		// Testing g to see if it is a primitive root.
		// The factors of primes[0]-1 are primes[1], primes[2], 2, factors[0], and factors[1].
		while (true) {
			if (   !g.modPow(p1.divide(primes[1]), primes[0]).equals(one)
				&& !g.modPow(p1.divide(primes[2]), primes[0]).equals(one)
				&& !g.modPow(p1.divide(one.add(one)), primes[0]).equals(one)
				&& !g.modPow(p1.divide(factors[0]), primes[0]).equals(one)
				&& !g.modPow(p1.divide(factors[1]), primes[0]).equals(one) ) {
					System.out.println(g.toString());
					return g;
			}
			
			else {
				g = g.add(one);
			}
		}
	} // end primRoot

}