// Eric Landquist
// Virginia Tech 
// October 26, 1998

// This class will be an individual's profile.

import java.util.Random;
import java.math.BigInteger;
import java.io.*;

class User {

// The user's name.
public String name;

// The number of bits in any number.
public static final int BITS = 1024;

// A buffer.
public byte[] buffer = new byte[BITS/8];
	
// The user's account number.
public BigInteger a;

// The user's RSA encryption key.
public BigInteger e;

// The user's RSA decryption key.
private BigInteger d;

// A two-dimensional array storing transaction numbers and and the corresponding x and y challenges.
private BigInteger[][] transactions = new BigInteger[3][50];
private int numTrans = 0;
// A temporary transaction number.
private BigInteger tempRandom;

// The Bank's encryption key.
public static final BigInteger eF = new BigInteger("31753334330785150921894247556736621874338756161197386784443128943016484609052387737301386274328387908878116471785658283254806375662817759052135684884271540381648730869694047818657115366581875466246609007215234708592315281388625426999307227281598582625973965498145364082908130504388456234882584510098319974757");

// The RSA modulus.
public static final BigInteger modulus = new BigInteger("67121633100854333760823216471326079676039838960980375144787957703044941147081296059123997261399910613390603844272962446505560297966424631213047304914323469022909185522090033023879429769168557156271032061067995076629568463341021245792743115819466961853594162377852172085064974026021473181363138895145026648893");

// A prime used as a public key.
public static final BigInteger p = new BigInteger("39176653485168937261236812439702609831448508122550980022664302727035222613253299329797670339773568468434872765577223730056267370338041289138500934868132480441658158377096480993729925515459639920746270053862138214932560550088228595580056165885844547511846459310603503565414543691466452907450326724132154736333");

// A prime that divides p-1
public static final BigInteger q = new BigInteger("1088240374588026035034355901102850273095791892293082778407341742417645072590369425827713064993710235234302021266033992501562982509390035809402803746337013345601615510474902249825831264318323331131840834829503839303682237502450794321668226830162348541995734980850097321261515102540734802984731297892559853787");

// A generator such that g^q = 1 (mod p)
public static final BigInteger g = new BigInteger("10");

// Private constants used in verification.
private BigInteger m;
private BigInteger b;

// Constants used in a challenge.
public BigInteger n;
public BigInteger c;

// The file containing all the user's information.
public RandomAccessFile infoFile;

	public User (String name) {
		// Identifying the user.
		this.name = name;

		// Getting the personal information out of the file.
		
		int bytesRead = BITS/8;
		try {
			infoFile = new RandomAccessFile(name+".usr", "rw");
			// Now get the personal information. First is the account number, then encryption key, and decryption key.
			// After that is all transaction numbers and corresponding challenge values.

			bytesRead = infoFile.read(buffer);
			a = new BigInteger(buffer);
			bytesRead = infoFile.read(buffer);
			e = new BigInteger(buffer);
			bytesRead = infoFile.read(buffer);
			d = new BigInteger(buffer);

			int i=0;
			bytesRead = infoFile.read(buffer);
			while (bytesRead > 0) {
				transactions[0][i] = new BigInteger(buffer);
				
				bytesRead = infoFile.read(buffer);
				
				if (bytesRead > 0) {
					transactions[1][i] = new BigInteger(buffer);
					bytesRead = infoFile.read(buffer);
					transactions[2][i] = new BigInteger(buffer);
				}
				i++;
				bytesRead = infoFile.read(buffer);
			} // end while() loop.
			
			numTrans = i;
			
			// Close the file.
			infoFile.close();
		} catch (IOException ioe) {
			error("Cannot get user info.");
			return;
		}
			
		// Now we have all the personal information read into the object.

	} // end constructor.
	
// Method:	error()

	public void error(String message){
		System.out.println("Error: " + message);
	} // end error()
	
// Method:	withdraw()
// Purpose:	To guide the withdrawal process of a user.
//			Returns a false if the transaction cannot be completed, 
//			that is, if the user tries to withdraw more money than he has.
// Parameter:	amount - the dollar amount to be withdrawn.

	public boolean withdraw (BigInteger amount, User vendor) {
		Bank bank = new Bank(this);
	
		// As before any transaction, we need to perform a key exchange.
		System.out.println();
		System.out.println("Performing a Diffie-Hellman Key Exchange between Bank and "+name+".");
		BigInteger random = new BigInteger(BITS, new Random()).mod(p);

		// The Bank returns their random number of the form g^B (mod p).
		BigInteger bRand = bank.keyExchange(g.modPow(random, p));
		
		// So the key is bRand^random (mod p).
		random = bRand.modPow(random, p);
		
		System.out.println();
		System.out.println("Performing a Diffie-Hellman Key Exchange between "+vendor.name+" and "+name+".");
		
		// Perform the Diffie Hellman key exchange with the vendor.
		BigInteger r2 = new BigInteger(BITS, new Random()).mod(p);
		BigInteger vRand = vendor.keyExchange(g.modPow(r2, p));

		r2 = vRand.modPow(r2, p);
		
		// Creating a completely different random number for use in the blind signature.
		BigInteger s = new BigInteger(BITS, new Random()).mod(p);
		
		System.out.println();
		System.out.println("Sending withdrawal request to the Bank.");
		
		
		// Now we make a withdrawal request, sending [random^eF, ra^eF, (random*amount)^(d*eF), (s^eF)(r2)(eB)] (mod modulus)
		BigInteger[] request = {random.modPow(eF, modulus), random.multiply(a.modPow(eF, modulus)).mod(modulus), random.multiply(amount.modPow(eF.multiply(d), modulus)), s.modPow(eF, modulus).multiply(r2).multiply(vendor.e).mod(modulus)};
		
		BigInteger[] coin = bank.withdraw(request);
		
		// Strip off the randomization.
		coin[1] = coin[1].multiply(random.modInverse(modulus)).mod(modulus);
		coin[2] = coin[2].multiply(s.modInverse(modulus)).mod(modulus);

		// If the coin is zero, then the withdrawal did not go through.
		if (coin[1].toString().equals("0")) {
			bank.update();
			return false;
		}
		
		// Check to make sure the coin is valid, i.e. the bank used it's decryption key as a signature.
		if (!amount.equals(decrypt(coin[1].modPow(eF, modulus)))){
			error("The coin is not valid.");
			bank.update();
			return false;
		}
		
		// Otherwise we have a valid coin, which we will give a file name based on the time.
		String name = String.valueOf(System.currentTimeMillis()%100000000)+".cnw";
		
		try {
			RandomAccessFile coinFile = new RandomAccessFile(name, "rw");
			byte[] bytes = decrypt(coin[0]).toByteArray();
			byte[] realBytes = new byte[BITS/8];
			if (bytes.length != BITS/8) {
				System.arraycopy(bytes, 0, realBytes, BITS/8 - bytes.length, bytes.length);
				coinFile.write(realBytes);
			}
			else
				coinFile.write(bytes);
			
			bytes = coin[1].toByteArray();
			realBytes = new byte[BITS/8];
			if (bytes.length != BITS/8) {
				System.arraycopy(bytes, 0, realBytes, BITS/8 - bytes.length, bytes.length);
				coinFile.write(realBytes);
			}
			else
				coinFile.write(bytes);
				
			bytes = coin[2].toByteArray();
			realBytes = new byte[BITS/8];
			if (bytes.length != BITS/8) {
				System.arraycopy(bytes, 0, realBytes, BITS/8 - bytes.length, bytes.length);
				coinFile.write(realBytes);
			}
			else
				coinFile.write(bytes);
			
			// The fourth and last part of the coin is now the transaction number between Alice and Bob.
			bytes = r2.toByteArray();
			realBytes = new byte[BITS/8];
			if (bytes.length != BITS/8) {
				System.arraycopy(bytes, 0, realBytes, BITS/8 - bytes.length, bytes.length);
				coinFile.write(realBytes);
			}
			else
				coinFile.write(bytes);
			
			coinFile.close();
		} catch (IOException ioe) {
			error("Could not create coin on file.");
			
			return false;
		}
		System.out.println();
		System.out.println("Successfully withdrew $" + amount + ". Coin is in file: " + name + ".");
		
		return true;
		
	} // end withdraw()
	
// Method:	deposit()
// Purpose:	To guide the deposit process of a user.
// Parameter:	coinFile - the file the coin is stored in

	public boolean deposit (String fileName, Bank bank) {
		
		System.out.println();
		System.out.println("Bank and "+name+" performing a Diffie Hellman Key Exchange.");
		
		// As before any transaction, we need to perform a key exchange.
		BigInteger random = new BigInteger(BITS, new Random()).mod(q);

		// The Bank returns their random number of the form g^B (mod p).
		BigInteger bRand = bank.keyExchange(g.modPow(random, p));
		
		// So the key is bRand^random (mod p).
		random = bRand.modPow(random, p);
		
		System.out.println();
		System.out.println("Accessing the coin.");
		
		// Open the coin file and extract the signed amount to deposit.
		BigInteger tempCoin[] = new BigInteger[2];
		try { 
		
			RandomAccessFile coinFile = new RandomAccessFile(fileName, "r");
			byte[] bytes = new byte[BITS/8];
			coinFile.read(bytes);
			tempCoin[0] = new BigInteger(bytes);
			coinFile.read(bytes);
			// Here have $^((dF)(dB))
			tempCoin[1] = decrypt(decrypt(new BigInteger(bytes)));
			coinFile.close();
			
			// Now we delete the coin, since it can never be used again.
			File coinFile2 = new File(fileName);
			coinFile2.delete();
			
		} catch (IOException ioe) {
			error("Could not open coin.");
			bank.update();
			return false;
		}
		
		System.out.println();
		System.out.println("Performing verification steps for the coin to be deposited.");
		
		// Generate a pair of arguments that will allow for verification.
		// m and b both need to be mod q, so let the value of [b/q] be worked on to get m.
		// Then the "full sized" value of b will be [b/q]q + b(mod q)
		b = decrypt(tempCoin[0]).mod(q);
		m = a;
		
		BigInteger u = g.modPow(b, p);
		BigInteger v = g.modPow(m, p);
		
		// Now generate the coin to send to the Bank.
		
		System.out.println();
		System.out.println("Depositing and verifying.");
		BigInteger[] coin = {random.modPow(eF, modulus), random.multiply(tempCoin[0]).mod(modulus), random.multiply(a.modPow(eF, modulus)), random.multiply(u).mod(p), random.multiply(v).mod(p), random.multiply(tempCoin[1]).mod(modulus) };

		boolean valid = bank.deposit(coin);

		if (!valid) 
			System.out.println("Coin not valid.");

		bank.update();
		return valid;

	} // end deposit()

// Method:	spend()
// Purpose:	To spend a coin.
// Parameter:	coinFile - the name of the file the coin is in.
//				vendor - the User the coin is being sent to.

	public int spend(String fileName, User vendor) {
		// Try to open the coin file.
		RandomAccessFile coinFile;
		BigInteger[] coin = new BigInteger[3];
		// The transaction number.
		BigInteger random;
		
		try {
			coinFile = new RandomAccessFile(fileName, "r");

			// If the file has length zero, then it did not previously exist, so it is an invalid coin.
			if(coinFile.length() == 0) {
				error("Coin does not exist.");
				return 0;
			}
			
			// Otherwise we proceed.
			byte[] buffer = new byte[BITS/8];
			coinFile.read(buffer);
			coin[0] = new BigInteger(buffer);
			coinFile.read(buffer);
			coin[1] = new BigInteger(buffer);
			coinFile.read(buffer);
			coin[2] = new BigInteger(buffer);
			coinFile.read(buffer);
			random = new BigInteger(buffer);
			coinFile.close();
		} catch(IOException ioe) {
			error("Could not open the coin on file.");
			return 0;
		}
	
		// Otherwise we may have a valid coin, unless of course, it is being double-spent.
		// Generate a pair of arguments that will allow for verification.
		
		m = a;
		b = coin[0].modPow(eF, modulus).mod(q);
		BigInteger u = g.modPow(b, p);
		BigInteger v = g.modPow(m, p);

		System.out.println();
		System.out.println("Generated random transaction number and verification numbers. Creating coin.");

		// Create the coin.
		BigInteger[] coin2 = {random.modPow(vendor.e, modulus), random.multiply(coin[0].modPow(eF, modulus)).mod(modulus), random.multiply(u).mod(p), random.multiply(v).mod(p), random.multiply(decrypt(coin[1]).modPow(vendor.e, modulus)).mod(modulus), coin[2]};
		
		// Send the vendor the coin, and he will return a 2 if the transaction was successful,
		// A 1 if it was sent to the wrong person, and a 0 if it was double spent.
		// Note here that User alice is sending her informatio to the vendor. This is jsut to simplify the program.
		// Later the ECash class will be modified to allow the transaction to occur with real anonymity.
		
		int valid = vendor.getCoin(coin2, this);
		
		// If the coin was not valid at all, then say so.
		if (valid == 0) {
			error("Transaction not verified. Transaction cancelled.");
		}
		
		// If the coin was not sent to the right person, then it doesn't make sense to delete the
		// coin, because it could have been an accidental mis-type.
		if (valid != 1) {
			// Delete the coin file.
			File coinFile2 = new File(fileName);
			coinFile2.delete();
		}
		
		return valid;

	} // end spend()
	
// Method:	keyExchange()
// Purpose:	To carry out a Diffie-Hellman key exchange with another User
// Parameter:	random - the reandom number being sent over.

	public BigInteger keyExchange(BigInteger random) {
		BigInteger zero = new BigInteger("0");
		BigInteger bRand = new BigInteger(BITS, new Random()).mod(p);
		// Since this random number will be used later, we store the transaction number in the user file.
		tempRandom = random.modPow(bRand, p);

		transactions[0][numTrans] = tempRandom;
		transactions[1][numTrans] = zero;
		transactions[2][numTrans] = zero;
		
		numTrans++;
		
		try {
			RandomAccessFile userFile = new RandomAccessFile(name+".usr", "rw");
			userFile.seek(3*numTrans*BITS/8);
			byte[] buffer = tempRandom.toByteArray();
			if (buffer.length != 128) {
				byte[] realBuffer = new byte[128];
				System.arraycopy(buffer, 0, realBuffer, BITS/8 - buffer.length, buffer.length);
				userFile.write(realBuffer);
			}
			else {
				userFile.write(buffer);
			}
			// Put in zeroes corresponding to the fact that there are no coordiantes for this 
			// transaction number yet.
			buffer = new byte[128];
			userFile.write(buffer);
			userFile.write(buffer);
		
		} catch(IOException ioe) {
			error("Could not open the user file.");
			return (g.modPow(bRand, p));
		}

		return (g.modPow(bRand, p));
	}

// Method:	getCoin()
// Purpose:	To process a coin being received from another User. Return 0 if not valid, 1 if to the wrong person, and 2 if OK.
// Parameters:	coin - The coin received from another User.
//				alice - the buyer, again, in later versions, this will change.

	public int getCoin(BigInteger[] coin, User alice) {
	
		// First get the random transaction number, and check against active transaction numbers.
		
		BigInteger tempTrans1 = decrypt(coin[0]);
		
		// Now we can check real quick to see if this coin was meant for this user.
		if (!coin[5].modPow(eF, modulus).equals(e.multiply(tempTrans1).mod(modulus))){
			error("Coin not intended for the user "+getName());
			return 1;
		}
		
		System.out.println();
		System.out.println("Checking the coin's validity and uniqueness of the transaction number.");
		
		// Here we check for the validity and uniqueness of a transaction number.
		int valid = 0;
		boolean unique = true;
		BigInteger[] coords = new BigInteger[2];
		int j=0;
		for (j=0; j<numTrans; j++) {
		
			if (transactions[0][j].equals(tempTrans1)){
				// If the coordinates corresponding with the transaction number are zero, then 
				// they haven't been used yet.
				if ((transactions[1][j].equals(new BigInteger("0"))) && (transactions[2][j].equals(new BigInteger("0")))){
					tempRandom = tempTrans1; 
					// If the transaction number is recorded, then we have a valid transaction.
				}
				// Otherwise, the transaction number has been used before.
				else {
					unique = false;
					coords[0] = transactions[1][j];
					coords[1] = transactions[2][j];
				}
				valid = 2;
				break;
			}
		}

		// If the transaction number is not present in the array, then stop the transaction.
		if(valid == 0) {
			System.out.println("Invalid transaction number.");
			return 0;
		}
		
		System.out.println();
		System.out.println(name+" making the challenge to "+alice.name+".");
		
		// Now we get the real transaction number from the Bank. i.e. tempTrans = r^eF.
		BigInteger tempTrans = coin[1].multiply(tempTrans1.modInverse(modulus)).mod(modulus);
		
		// Extract the two challenge values.
		c = coin[2].multiply(tempTrans1.modInverse(p)).mod(p);
		n = coin[3].multiply(tempTrans1.modInverse(p)).mod(p);
		
		// Then make the challenge.
		BigInteger[] coords2 = challenge(alice);

		// If the coin is not valid, the transaction does not process
		BigInteger zero = new BigInteger("0");
		if (coords2[0].equals(zero) && coords2[1].equals(zero)){
			error("Authorization invalid. Transaction cancelled.");
			return 0;
		}
	
		// Again, if Alice double-spent, then we can double check with her personal information.
		if (!unique) {
			BigInteger slope = (coords[1].subtract(coords2[1])).multiply((coords[0].subtract(coords2[0])).modInverse(q)).mod(q);

			error("Use of coin twice. Transaction cancelled.");
			
			boolean identified = Bank.check(slope.modPow(eF, modulus));
			
			if (!identified) {
				error("No match found for double spender.");
			}
			
			// At this point, we can also send the bank the other half of the information to identify alice,
			// since the Bank is the only one who can positively identify Alice.
			return 0;
		}

		// If it cleared, then we can add in the coordinates.
		// Given the size of the random transaction numbers, the odds that we will get
		// 	two different valid transactions with the same number is extremely small,
		// 	about the odds that God didn't create the Universe, so we will say that such
		// a case is impossible. Thus in the block immediately above, if the first if statement went through,
		// we assume the second will as well.

		transactions[1][j] = coords2[0];
		transactions[2][j] = coords2[1];
		
		// Now we can go ahead and check how much money was sent and then create the coin.
		BigInteger dollars = decrypt(coin[4].multiply(tempTrans1.modInverse(modulus)).mod(modulus).modPow(eF, modulus));
	
		// We will give the coin a file name based on the time.
		String coinName = String.valueOf(System.currentTimeMillis()%100000000)+".cns";
		
		try {
			
			RandomAccessFile coinFile = new RandomAccessFile(coinName, "rw");
			byte[] tempBytes = tempTrans.toByteArray();
			if(tempBytes.length != BITS/8) {
				byte[] realBytes = new byte[BITS/8];
				System.arraycopy(tempBytes, 0, realBytes, BITS/8 - tempBytes.length, tempBytes.length);
				coinFile.write(realBytes);
			}
			else
				coinFile.write(tempBytes);

			// Here writing $^((eF)(d)).
			coinFile.write(coin[4].multiply(tempTrans1.modInverse(modulus)).mod(modulus).toByteArray());
			coinFile.close();
		} catch (IOException ioe) {
			error("Could not create coin on file.");
			return 0;
		}
		
		System.out.println("Successfully spent/received $" + dollars.toString() + ". Coin is in file: " + coinName + ".");
	
		// Now write the new transaction numbers to the usr file.
		try {
			infoFile = new RandomAccessFile (name+".usr", "rw");
			infoFile.seek(384*(j+1));
			for (int l=j; l<numTrans; l++) {
				byte[] tempBytes = transactions[0][l].toByteArray();
				byte[] realBytes = new byte[BITS/8];
				if(tempBytes.length != BITS/8) {
					System.arraycopy(tempBytes, 0, realBytes, BITS/8 - tempBytes.length, tempBytes.length);
					infoFile.write(realBytes);
				}
				else
					infoFile.write(tempBytes);
			
				tempBytes = transactions[1][l].toByteArray();
				realBytes = new byte[BITS/8];
				if(tempBytes.length != BITS/8) {
					System.arraycopy(tempBytes, 0, realBytes, BITS/8 - tempBytes.length, tempBytes.length);
					infoFile.write(realBytes);
				}
				else
					infoFile.write(tempBytes);
				
				tempBytes = transactions[2][l].toByteArray();
				realBytes = new byte[BITS/8];
				if(tempBytes.length != BITS/8) {
					System.arraycopy(tempBytes, 0, realBytes, BITS/8 - tempBytes.length, tempBytes.length);
					infoFile.write(realBytes);
				}
				else
					infoFile.write(tempBytes);
			} // end for loop
			
			infoFile.close();
			
		} catch(IOException ioe) {
			error("Could not update user file.");
		}	
		
		return 2;
		
	} // end getCoin()
	
// Method:	challenge()
// Purpose: To challenge the validity of a deposit

	public BigInteger[] challenge(User alice) {
	
		System.out.println();
		System.out.println("Doing the challenge.");
	
		BigInteger[] x_y = alice.respond(new BigInteger(BITS, new Random()).mod(q));
		if( checkCoords(x_y[0], x_y[1]))
			return x_y;
		else {
			BigInteger zero = new BigInteger("0");
			BigInteger[] zerozero = {zero, zero};
			return zerozero;
		}
	}
	
// Method:	respond()
// Purpose:	To respond to a challenge by the vendor
// Parameter:	x - the x-coordinate of a pair.

	public BigInteger[] respond(BigInteger x) {
		// The second element of the pair is the y coordinate for the line.
		BigInteger[] response = {x, m.multiply(x).add(b).mod(q)};
		
		return response;
	} // end respond()

// Method:	checkCoords()
// Purpose:	To check the two coordinates to see if they are in fact valid.
// Parameters:	x, y - the x and y coordinate pair.

public boolean checkCoords(BigInteger x, BigInteger y) {
		if(g.modPow(y, p).equals(n.modPow(x, p).multiply(c).mod(p)))
			return true;
		
		else 
			return false;
	}

// Method: 	encrypt()
// Purpose:	To encrypt an integer using the RSA protocol.

	public BigInteger encrypt(BigInteger m) {
		return m.modPow(e, modulus);
	}

// Method:	decrypt()
// Purpose:	To decrypt an integer, using the RSA protocol.

	public BigInteger decrypt(BigInteger c) {
		return c.modPow(d, modulus);
	}

	public String getName(){
		return name;
	}
	

}