// Eric Landquist
// Virginia Tech
// October 11, 1998

// ECash.java

import java.util.Random;
import java.math.BigInteger;
import java.io.*;
//import java.lang.ArrayIndexOutOfBoundsException;

// This class will implement an electronic cash system.
// A separate class is used for the Bank.

class ECash {

// The users.
public static String[] users = new String[Bank.SIZE];

// The corresponding file names.
public static String[] files = new String[Bank.SIZE];

// The actual list size.
public static int size;

public static final int BITS = 1024;

// The factors of the modulus.
private static final BigInteger p1 = new BigInteger("7170000514658894417055574270757891168897026865705261405803275335656485849781540542270681369440065154052312531245236224141311698343507846807830263847900867");
private static final BigInteger p2 = new BigInteger("9361454432761303383576945134778282370762823022650607807505926311460694121927976905088662608803971809334091963782601105713853582684972194665452970652321279");


// Method:	ECash()
// Constructor

	public ECash() {
	}
	
// Method:	main()

	public static void main(String args[]) {
	
		// The amount of money we are working with.
		BigInteger dollars;
	
		// There must be three arguments: login, transaction, and amount.
		if (!((args.length == 3) || (args.length == 4))) {
			error("Usage: java ECash [login] [c | d | coinFile | w] [credit | coinFile | vendor | amount] [|||vendor]");
			return;
		}
		
		// Creating an account.
		if (args[1].equals("c") || args[1].equals("C")) {
			RandomAccessFile userFile;
			RandomAccessFile bankFile;
			
			try {
				userFile = new RandomAccessFile(args[0]+".usr", "rw");
				bankFile = new RandomAccessFile(args[0]+".bnk", "rw");
				
				System.out.println();
				System.out.println("Creating user and bank files for user "+args[0]+".");
				
				// Create the keys.
				byte[] buffer = new byte[3*BITS/8];
				// First the account number.
				BigInteger a = new BigInteger(BITS, new Random()).mod(Bank.q);
				
				//Now the encryption and decryption keys.
				int length = 0;
				BigInteger one = new BigInteger("1");
				BigInteger e = one;
				BigInteger d = one;
				
				// We want a decryption key with 128 bytes.
				System.out.println();
				System.out.println("Creating public and private keys for "+args[0]+". This will take a couple minutes.");

				while (length != BITS/8) {
					System.out.print(".");
					try {
						e = new BigInteger(BITS, 20, new Random()).mod(Bank.modulus);
						d = e.modInverse(p1.subtract(one).multiply(p2.subtract(one)));
						length = d.toByteArray().length;
					} catch(ArithmeticException ae){
						continue;
					} catch(ArrayIndexOutOfBoundsException aioobe){
						continue;
					}
				}
				
				System.out.println();
				System.out.println("Keys created. Writing to file.");
				
				System.arraycopy(a.toByteArray(), 0, buffer, BITS/8 - a.toByteArray().length, a.toByteArray().length);
				System.arraycopy(e.toByteArray(), 0, buffer, BITS/4 - e.toByteArray().length, e.toByteArray().length);
				System.arraycopy(d.toByteArray(), 0, buffer, 3*BITS/8 - d.toByteArray().length, d.toByteArray().length);
				
				userFile.write(buffer);
				
				userFile.close();
				
				// Now create the bank file, the information the bank sees.
				// The account number, the encryption key, and the amount of money to begin hte account with.
				byte[] money = new byte[BITS/8];
				dollars = new BigInteger(args[2]);
				money[0] = (byte) dollars.toByteArray().length;
				System.arraycopy(dollars.toByteArray(), 0, money, BITS/8 - money[0], money[0]);
				System.arraycopy(money, 0, buffer, BITS/4, BITS/8);
				
				bankFile.write(buffer);
				bankFile.close();
			} catch (NumberFormatException nfe) {
				error("Could not create account.");
				return;
			} catch (IOException ioe) {
				error("Could not open or close file.");
				return;
			}
			
			System.out.println();
			System.out.println("Account successfully created.");
			return;
		}
		
		// Working with withdrawals.
		else if (args[1].equals("w") || args[1].equals("W")) {
			if (args.length != 4){
				error ("Need four arguments for withdrawals.");
				return;
			} 
			User alice = new User(args[0]);
			User bob = new User(args[3]);
			try {
				dollars = new BigInteger(args[2]);
			} catch (NumberFormatException nfe) {
				error("Dollar amount needs to be an integer");
				return;
			}
		
			System.out.println();
			System.out.println("Withdrawing $"+dollars+" from "+args[0]+"'s account for "+args[3]+"."); 
			alice.withdraw(dollars, bob);
		}
		
		// Working with spending a coin. Since we want to preserve anonymity in this transaction,
		// this class will be used to guide the transaction.
		else if (args[1].length() > 1) {
			User alice = new User(args[0]);
			User vendor = new User(args[2]);
		//	spend(alice, vendor, args[1]);
			System.out.println();
			System.out.println(args[0] + " spending the coin on the vendor, "+ args[2]+".");
			alice.spend(args[1], vendor);
		}
		
		// Depositing a coin
		else if (args[1].equals("d") || args[1].equals("D")) {
			User alice = new User(args[0]);
			Bank bank = new Bank(alice);
			// The argument for depositing is a file name for a coin.
			System.out.println();
			System.out.println(args[0] + "depositing the coin at the Bank.");
			alice.deposit(args[2], bank);
		}
		
		else {
			error("Transaction not valid. Must be \"w\", \"c\", or \"d.\""); 
			return;
		}

	} // end main()

// Method: 	error()
// Purpose:	To give an error if one occurs.
// Parameter:	message - the error message

	public static void error(String message) {
		System.out.println("Error: "+message);
	}
	

// Method: 	spend()
// Purpose:	To arbitrate the spending process between alice and the vendor.
// Parameters:	alice - The customer
//				vendor - the vendor
//				coinFile - the file Alice's coin is in.

} // end class ECash