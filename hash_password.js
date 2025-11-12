const bcrypt = require('bcryptjs');
const readline = require('readline');

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

// Prompt the user to enter a new password
rl.question('Enter the new password to hash: ', (password) => {
  if (!password) {
    console.error('Password cannot be empty.');
    rl.close();
    return;
  }

  // Generate a salt and hash the password
  bcrypt.genSalt(10, (err, salt) => {
    if (err) {
      console.error('Error generating salt:', err);
      rl.close();
      return;
    }
    bcrypt.hash(password, salt, (err, hash) => {
      if (err) {
        console.error('Error hashing password:', err);
      } else {
        console.log('\nPassword hashing complete!');
        console.log('Copy the following hash and use it in your SQL UPDATE statement:');
        console.log('----------------------------------------------------------------');
        console.log(hash);
        console.log('----------------------------------------------------------------');
      }
      rl.close();
    });
  });
});