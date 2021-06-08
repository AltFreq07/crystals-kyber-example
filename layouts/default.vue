<template>
  <v-app dark>
    <v-main>
      <v-container>
        <h3>Crystals Kyber Example</h3>
        <h4>Unilaterally Authenticated Key Exchange</h4>

        <br />
        <v-btn @click="greet">Click Here</v-btn><br />
        <p class="text-truncate" style="max-width: 1000px">
          Alice wants to send Bob an encrypted message, Bob generates a
          public/secret key pair and lets Alice know the public key <br /><br />
          Bobs Private Key: {{ bPrivate }}
        </p>
        <p class="text-truncate" style="max-width: 1000px">
          Bobs Public Key: {{ bPublic }}
        </p>
        <br />
        <br />
        <p>
          Alice initiates key exchange using Bobs public key and generates a
          256bit symmetric encryption key and an encapsulation key. The
          symmetric key will be used to encrypt traffic between Bob and Alice as
          it is faster than asymmetrical
        </p>
        <br />
        <p class="text-truncate" style="max-width: 1000px">
          Alice's shared symmetrical key:
          <span style="color: LightGreen"> {{ aSymKey }}</span
          ><br /><br />
          The encapsulation key to send back to Bob {{ encapKey }}
        </p>
        <br />
        <p>
          Bob will then use the received encapsulation key with his private key
          to generate the same shared symmetrical key that Alice has
        </p>
        <p>
          Bob's shared symmetrical key:<span style="color: LightGreen">
            {{ bSymKey }}</span
          >
        </p></v-container
      >
    </v-main>
  </v-app>
</template>

<script>
export default {
  data() {
    return {
      result: null,
      bPrivate: '',
      bPublic: '',
      aSymKey: '',
      bSymKey: '',
      encapKey: '',
    }
  },
  mounted() {},
  methods: {
    // async greet() {
    //   const wasm = import('../node_modules/hello-wasm/hello_wasm.js')
    //   const greet = (await wasm).greet
    //   greet()
    // },
    greet() {
      /*  eslint-disable */
      //       var pk_sk = K768_KeyGen();
      // var pk = pk_sk[0];
      // var sk = pk_sk[1];
      const K768 = require('crystals-kyber')
      var pk_sk = K768.K768_KeyGen()

      this.bPublic = this.base64ArrayBuffer(pk_sk[0])
      this.bPrivate = this.base64ArrayBuffer(pk_sk[1])

      var c_ss = K768.K768_Encrypt(pk_sk[0])
      this.encapKey = this.base64ArrayBuffer(c_ss[0])
      this.aSymKey = this.base64ArrayBuffer(c_ss[1])
      // var c = c_ss[0]
      // var ss1 = c_ss[1]
      // var ss2 = K768_Decrypt(c,sk);
      var ss2 = K768.K768_Decrypt(c_ss[0], pk_sk[1])
      this.bSymKey = this.base64ArrayBuffer(ss2)
      // console.log(ss1)
      // console.log(ss2)
      /*  eslint-enable */
    },
    base64ArrayBuffer(arrayBuffer) {
      let base64 = ''
      const encodings =
        'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'

      const bytes = new Uint8Array(arrayBuffer)
      const byteLength = bytes.byteLength
      const byteRemainder = byteLength % 3
      const mainLength = byteLength - byteRemainder

      let a, b, c, d
      let chunk

      // Main loop deals with bytes in chunks of 3
      for (let i = 0; i < mainLength; i = i + 3) {
        // Combine the three bytes into a single integer
        chunk = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2]

        // Use bitmasks to extract 6-bit segments from the triplet
        a = (chunk & 16515072) >> 18 // 16515072 = (2^6 - 1) << 18
        b = (chunk & 258048) >> 12 // 258048   = (2^6 - 1) << 12
        c = (chunk & 4032) >> 6 // 4032     = (2^6 - 1) << 6
        d = chunk & 63 // 63       = 2^6 - 1

        // Convert the raw binary segments to the appropriate ASCII encoding
        base64 += encodings[a] + encodings[b] + encodings[c] + encodings[d]
      }

      // Deal with the remaining bytes and padding
      if (byteRemainder === 1) {
        chunk = bytes[mainLength]

        a = (chunk & 252) >> 2 // 252 = (2^6 - 1) << 2

        // Set the 4 least significant bits to zero
        b = (chunk & 3) << 4 // 3   = 2^2 - 1

        base64 += encodings[a] + encodings[b] + '=='
      } else if (byteRemainder === 2) {
        chunk = (bytes[mainLength] << 8) | bytes[mainLength + 1]

        a = (chunk & 64512) >> 10 // 64512 = (2^6 - 1) << 10
        b = (chunk & 1008) >> 4 // 1008  = (2^6 - 1) << 4

        // Set the 2 least significant bits to zero
        c = (chunk & 15) << 2 // 15    = 2^4 - 1

        base64 += encodings[a] + encodings[b] + encodings[c] + '='
      }

      return base64
    },
  },
}
</script>
