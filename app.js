const fs = require("fs");
const express = require("express");
const multer = require("multer");
var bodyParser = require('body-parser')
const OAuth2Data = require("./credentials.json");
const bcrypt = require("bcrypt");
const crypto = require("crypto");
//const fileUpload = require("express-fileupload");
const Readable = require('stream').Readable; 
const os = require('os');

var name,pic

const { google, drive_v3 } = require("googleapis");

const app = express();

// app.use(
//   fileUpload()
// );

const CLIENT_ID = "646414451405-p0jlaulc6jmbp9q8baerkml03d8mmhq4.apps.googleusercontent.com";
const CLIENT_SECRET = "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";
const REDIRECT_URL = OAuth2Data.web.redirect_uris[0];

const oAuth2Client = new google.auth.OAuth2(
  CLIENT_ID,
  CLIENT_SECRET,
  REDIRECT_URL
);
var authed = false;

// If modifying these scopes, delete token.json.
//const SCOPES ="https://www.googleapis.com/auth/drive https://www.googleapis.com/auth/drive.file https://www.googleapis.com/auth/userinfo.profile";
// const drive = google.drive({ version: "v3",oAuth2Client  });

//   const fileId = '1bCzSrMAqMfTuaNm6r-7u0vpllSu8ZkO0'
//   const password = '123456'

//   drive.files.get(
//     { fileId: fileId,
//       alt: "media"
//     }
//   ).then(res => {
//     var final = JSON.stringify(res.data);
    
//     var bob_salt = final.substr(0,32)
//     var bob_payload = final.substr(32, final.length)
    
//     bob_payload = Buffer.from(bob_payload, 'base64').toString('hex')
//     const bob_iv = bob_payload.substr(0,32)
//     const bob_encrypted = bob_payload.substr(32, bob_payload.length - 32 - 32)
//     const bob_auth_tag = bob_payload.substr(bob_payload.length - 32, 32);
    
//     // console.log({
//     //   bob_salt,
//     //   bob_iv,
//     //   bob_payload,
//     //   bob_encrypted,
//     //   bob_auth_tag
//     // })
    
//     var bob_hash = bcrypt.hashSync(password, bob_salt).slice(0,32)
//     console.log("bob_hash: " + bob_hash)
    
    
//     try {
//       const decipher = crypto.createDecipheriv(
//         'aes-256-gcm', 
//         Buffer.from(bob_hash),
//         Buffer.from(bob_iv, 'hex')
//       );
    
//       decipher.setAuthTag(Buffer.from(bob_auth_tag, 'hex'))
    
//       let decrypted = decipher.update(bob_encrypted, 'hex', 'utf-8')
//       decrypted += decipher.final('utf-8')
    
//       console.log("Decrypted Message: " + decrypted)
//     } catch(error) {
//         console.log("error: " + error.message)
//     }
//   })
app.set("view engine", "ejs");


var password = "123456"
const message = "this is my message";
console.log("Tihs is the text: " + message);
console.log("This is the user password : " + password);
console.log("Encrypting ...");
const salt = bcrypt.genSaltSync()
console.log("Generated Salt : " + salt);
var hash = bcrypt.hashSync(password, salt).slice(0,32)
console.log("Generated Hash : " + hash)


const IV = crypto.randomBytes(16);
const cipher = crypto.createCipheriv('aes-256-gcm', hash, IV);

let encrypted = cipher.update(message, 'utf-8','hex')
encrypted += cipher.final('hex')

const auth_tag = cipher.getAuthTag().toString('hex')

console.table({
  IV: IV.toString('hex'),
  encrypted: encrypted,
  auth_tag: auth_tag,
  salt: salt
})

const payload = IV.toString('hex') + encrypted + auth_tag;

var payload64 = Buffer.from(payload, 'hex').toString('base64')
// console.log("Generate payload to upload in Google drive : " + payload)
var final = salt + payload64;
console.log("Generate payload to upload in Google drive : " + final)


console.log("Now, decrypring ... ");
var bob_salt = final.substr(0,32)
var bob_payload = final.substr(32, final.length)

bob_payload = Buffer.from(payload64, 'base64').toString('hex')
const bob_iv = bob_payload.substr(0,32)
const bob_encrypted = bob_payload.substr(32, bob_payload.length - 32 - 32)
const bob_auth_tag = bob_payload.substr(bob_payload.length - 32, 32);
console.log("Decrypted information: ")

console.table({
  salt: bob_salt,
  IV: bob_iv,
  encrpyted: bob_encrypted,
  auth_tag: bob_auth_tag
})

var bob_hash = bcrypt.hashSync(password, bob_salt).slice(0,32)

try {
  const decipher = crypto.createDecipheriv(
    'aes-256-gcm', 
    Buffer.from(bob_hash),
    Buffer.from(bob_iv, 'hex')
  );

  decipher.setAuthTag(Buffer.from(bob_auth_tag, 'hex'))

  let decrypted = decipher.update(bob_encrypted, 'hex', 'utf-8')
  decrypted += decipher.final('utf-8')

  console.log("Decrypted Message: " + decrypted)
} catch(error) {
    console.log("error: " + error.message)
}


//var Storage = multer.memoryStorage({
  // destination: function (req, file, callback) {
  //   callback(null, "/images");
  // },
  // metadata: function (req, file, callback) {
  //   callback(null, { fieldName: file.fieldName})
  // },
  // filename: function (req, file, callback) {
  //   // const multerText = Buffer.from(req.file.buffer).toString("utf-8"); 
  //   // console.log("req body: " + multerText);
  //   var name = file.originalname
  //   callback(null, name);
  // },
// });

var Storage = multer.diskStorage({
  // destination: function (req, file, callback) {
  //   callback(null, "./images");
  // },
  filename: function (req, file, callback) {
    callback(null, file.originalname);
  },
});

const fileFilter = (req, file, cb) => {
  if (file.mimetype == 'text/plain') { // checking the MIME type of the uploaded fil
      cb(null, true);
  } else {
      cb(null, false);
  }
}

const storage = multer.memoryStorage();

var upload = multer({
  storage: Storage,
}).single("file"); //Field name and max count

app.get("/", (req, res) => {
  if (!authed) {
    // Generate an OAuth URL and redirect there
    var url = oAuth2Client.generateAuthUrl({
      access_type: "offline",
      scope: SCOPES,
    });
    console.log("The url: " + url);
    res.render("index", { url: url });
  } else {
    var oauth2 = google.oauth2({
      auth: oAuth2Client,
      version: "v2",
    });
    oauth2.userinfo.get(function (err, response) {
      if (err) {
        console.log(err);
      } else {
        console.log(response.data);
        name = response.data.name
        pic = response.data.picture
        res.render("success", {
          name: response.data.name,
          pic: response.data.picture,
          success:false
        });
      }
    });
  }
});

app.get("/files", (req, res) => {
    const drive = google.drive({ version: "v3",auth:oAuth2Client  });
    drive.files.list({
      includeRemoved: false
    }, function(err, data) {
      if(err) {
        console.log("error " + err);
      } else {
        //res.redirect('/home')
        res.send(JSON.stringify(data.data.files));
        console.log(JSON.stringify(data));
      }
    })
})

app.get("/GetAndViewFile", (req, res) => {
  const drive = google.drive({ version: "v3",auth:oAuth2Client  });

  const fileId = '1bCzSrMAqMfTuaNm6r-7u0vpllSu8ZkO0'
  const password = '123456'

  drive.files.get(
    { fileId: fileId,
      alt: "media"
    }
  ).then(res => {
    var final = JSON.stringify(res.data);
    
    var bob_salt = final.substr(0,32)
    var bob_payload = final.substr(32, final.length)
    
    bob_payload = Buffer.from(bob_payload, 'base64').toString('hex')
    const bob_iv = bob_payload.substr(0,32)
    const bob_encrypted = bob_payload.substr(32, bob_payload.length - 32 - 32)
    const bob_auth_tag = bob_payload.substr(bob_payload.length - 32, 32);
    
    // console.log({
    //   bob_salt,
    //   bob_iv,
    //   bob_payload,
    //   bob_encrypted,
    //   bob_auth_tag
    // })
    
    var bob_hash = bcrypt.hashSync(password, bob_salt).slice(0,32)
    console.log("bob_hash: " + bob_hash)
    
    
    try {
      const decipher = crypto.createDecipheriv(
        'aes-256-gcm', 
        Buffer.from(bob_hash),
        Buffer.from(bob_iv, 'hex')
      );
    
      decipher.setAuthTag(Buffer.from(bob_auth_tag, 'hex'))
    
      let decrypted = decipher.update(bob_encrypted, 'hex', 'utf-8')
      decrypted += decipher.final('utf-8')
    
      console.log("Decrypted Message: " + decrypted)
    } catch(error) {
        console.log("error: " + error.message)
    }
  })
})

app.get("/updateFile", (req, res) => {
  const drive = google.drive({ version: "v3",auth:oAuth2Client  });

  const media = {
    mimeType: 'text/plain',
    body: "Hi, welcome here!",
  }; 

    drive.files.update({
      fileId: "12hNMvL2tFIMo2iOpp-HtNMBlmDoh5Q_U",
      media: media,
    }, (err, res) => {
      if (err) {
        console.log(err);
      } else {
        console.log(res);
      }
  });
})

const storage_1 = multer.memoryStorage();


const upload_1 = multer({
  fileFilter,
  storage_1
});

app.post("/uploadFile", upload, (req, res) => { 
    var file = req.file;
    if (!file) {
      const error = new Error("Please upload a file");
      error.httpStatusCode = 400;
      //return next(error);
    }

    const drive = google.drive({ version: "v3", auth:oAuth2Client  });

    // fs.writeFileSync(req.file.path, multerText);

    // const form = new FormData();
    // form.append("metadata", JSON.stringify(metadata), { 
    //   type: "application/json",
    // });
    // form.append("file", fs.createReadStream(req.file.path));

    const multerText = Buffer.from(req.file.buffer).toString("utf-8"); 
    console.log("req body: " + multerText);

    //fs.writeFileSync(req.file.path, multerText);

    const metadata = {
      name: req.file.filename
    };

    const media = {
      body: 'f',
      mimeType: req.file.mimetype
    };

    drive.files.create(
      {
        media: media,
        resource: metadata,
        fields: "id",
      },
      (err, file) => {
        if (err) {
          // Handle error
          console.error(err);
        } else {
          fs.unlinkSync(req.file.path)
          res.render("success",{name:name,pic:pic,success:true})
        }
      }
    );

    // const fileMetadata = {
    //   name: req.file.filename,
    // };
    // const media = {
    //   mimeType: req.file.mimetype,
    //   body: fs.createReadStream(req.file.path),
    // };

    // drive.files.create(
    //   {
    //     resource: fileMetadata,
    //     media: media,
    //     fields: "id",
    //   },
    //   (err, file) => {
    //     if (err) {
    //       // Handle error
    //       console.error(err);
    //     } else {
    //       fs.unlinkSync(req.file.path)
    //       res.render("success",{name:name,pic:pic,success:true})
    //     }
    //   }
    // );
});

app.post("/upload", (req, res) => {
  upload(req, res, function (err) {

    let fileContent = fs.readFileSync(req.file.path);
    let userPassword = req.body.password;

    console.log("User Password: " + userPassword);
    console.log("File Content : " + fileContent);

    // encryption

    const salt = bcrypt.genSaltSync(2)
    console.log("salt: " + salt);
    var hash = bcrypt.hashSync(userPassword, salt).slice(0,32)
    console.log("hash: " + hash)

    const IV = crypto.randomBytes(16);
    console.log(hash.length)
    const cipher = crypto.createCipheriv('aes-256-gcm', hash, IV);

    let encrypted = cipher.update(fileContent, 'utf-8','hex')
    encrypted += cipher.final('hex')

    const auth_tag = cipher.getAuthTag().toString('hex')

    // console.table({
    //   IV: IV.toString('hex'),
    //   encrypted: encrypted,
    //   auth_tag: auth_tag,
    //   salt: salt
    // })

    const payload = IV.toString('hex') + encrypted + auth_tag;

    var payload64 = Buffer.from(payload, 'hex').toString('base64')
    //console.log("payload : " + payload)
    var final = salt + payload64;
    console.log("Encrypted payload to upload : " + final)

    // if (!req.files) {
    //   return res.status(400).send("No files were uploaded.");
    // }
  
    // var logFile = req.files.file
    
    // console.log(logFile);
    // var buffer = logFile.data.toString('utf8');
    // console.log(buffer);

    if (err) {
      console.log(err);
      return res.end("Something went wrong");
    } 
    else {
      console.log(req.file.path);
      const drive = google.drive({ version: "v3",auth:oAuth2Client  });
      const fileMetadata = {
        name: req.file.filename,
      };

    var stream = fs.createWriteStream(req.file.path, {flags: 'w'});
    //var data = "Hello, World!\n";
    stream.write(final, function() {
      // Now the data has been written.
    });
    
    const media = {
        mimeType: req.file.mimetype,
        body: fs.createReadStream(req.file.path),
      };
      drive.files.create(
        {
          resource: fileMetadata,
          media: media,
          fields: "id",
        },
        (err, file) => {
          if (err) {
            // Handle error
            console.error(err);
          } else {
            fs.unlinkSync(req.file.path)
            res.render("success",{name:name,pic:pic,success:true})
          }
        }
      );
    }
  });
});

app.get('/logout',(req,res) => {
    authed = false
    res.redirect('/')
})

app.get("/google/callback", function (req, res) {
  const code = req.query.code;
  if (code) {
    // Get an access token based on our OAuth code
    oAuth2Client.getToken(code, function (err, tokens) {
      if (err) {
        console.log("Error authenticating");
        console.log(err);
      } else {
        console.log("Successfully authenticated");
        console.log(tokens)
        oAuth2Client.setCredentials(tokens);


        authed = true;
        res.redirect("/");
      }
    });
  }
});

app.listen(5000, () => {
  console.log("App is listening on Port 5000");
});