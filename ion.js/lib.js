const fetch = require("cross-fetch");
const randomBytes = require("randombytes");
const ed25519 = require("@transmute/did-key-ed25519");
const secp256k1 = require("@transmute/did-key-secp256k1");
const RawIonSdk = require("@decentralized-identity/ion-sdk");
const ProofOfWorkSDK = require("ion-pow-sdk");

async function _generateKeyPair(factory) {
  const keyPair = await factory.generate({
    secureRandom: () => randomBytes(32),
  });
  return await keyPair.export({
    type: "JsonWebKey2020",
    privateKey: true,
  });
}

var ION = (globalThis.ION = {
  SDK: RawIonSdk,
  async generateKeyPair(signType, keypairType) {
    switch (signType) {
      case "Ed25519":
      case "EdDSA":
        return await _generateKeyPair(ed25519.Ed25519KeyPair, keypairType);

      case "secp256k1":
      case "ES256K":
      default:
        return await _generateKeyPair(secp256k1.Secp256k1KeyPair, keypairType);
    }
  },
  async from(keypair) {
    return await secp256k1.Secp256k1KeyPair.from(keypair);
  },
  async resolve(didUri, options = {}) {
    return fetch(
      (options.nodeEndpoint ||
        "https://beta.discover.did.microsoft.com/1.0/identifiers/") + didUri
    ).then((response) => {
      if (response.status >= 400) throw new Error("Not Found");
      return response.json();
    });
  },
});

ION.AnchorRequest = class {
  constructor(requestBody, options = {}) {
    this.body = requestBody;
    this.challengeEndpoint = options.challengeEndpoint;
    this.solutionEndpoint = options.solutionEndpoint;
    if (!this.challengeEndpoint || !this.solutionEndpoint) {
      this.challengeEndpoint =
        "https://beta.ion.msidentity.com/api/v1.0/proof-of-work-challenge";
      this.solutionEndpoint =
        "https://beta.ion.msidentity.com/api/v1.0/operations";
    }
  }
  async submit() {
    return ProofOfWorkSDK.submitIonRequest(
      this.challengeEndpoint,
      this.solutionEndpoint,
      JSON.stringify(this.body)
    );
  }
};

ION.DID = class {
  constructor(options = {}) {
    this._ops = options.ops || [];
    if (!this._ops[0]) {
      this._ops[0] = this.generateOperation(
        "create",
        options.content || {},
        false
      );
    }
  }

  async getState() {
    return {
      shortForm: await this.getURI("short"),
      longForm: await this.getURI(),
      ops: await this.getAllOperations(),
    };
  }

  getAllOperations() {
    return Promise.all(this._ops);
  }

  async getOperation(index) {
    return this._ops[index];
  }

  async getURI(form) {
    const create = await this.getOperation(0);
    console.log(create);
    this._longForm =
      this._longForm ||
      RawIonSdk.IonDid.createLongFormDid({
        recoveryKey: create.recovery.publicKeyJwk,
        updateKey: create.update.publicKeyJwk,
        document: create.content,
      });
    return !form || form === "long"
      ? this._longForm
      : this._longForm.split(":").slice(0, -1).join(":");
  }

  async getSuffix() {
    return (await this.getURI("short")).split(":").pop();
  }

  async generateOperation(type, content, commit = true) {
    let ops = await this.getAllOperations();
    let lastOp = ops[ops.length - 1];
    if (lastOp && lastOp.operation === "deactivate") {
      throw "Cannot perform further operations on a deactivated DID";
    }
    let op = {
      operation: type,
      content: content,
    };
    if (type !== "create") {
      op.previous = ops.reduce((last, op) => {
        return op.operation === type ||
          (op.operation === "recover" &&
            (type === "deactivate" || type === "update"))
          ? op
          : last;
      }, ops[0]);
    }
    if (type === "create" || type === "recover") {
      op.recovery = await ION.generateKeyPair();
    }
    if (type !== "deactivate") {
      op.update = await ION.generateKeyPair();
    }
    if (commit) this._ops.push(op);
    return op;
  }

  async generateRequest(payload = 0, options = {}) {
    const op =
      typeof payload === "number" ? await this.getOperation(payload) : payload;
    switch (op.operation) {
      case "update":
        return RawIonSdk.IonRequest.createUpdateRequest({
          didSuffix: await this.getSuffix(),
          signer:
            options.signer ||
            RawIonSdk.LocalSigner.create(op.previous.update.privateJwk),
          updatePublicKey: op.previous.update.publicKeyJwk,
          nextUpdatePublicKey: op.update.publicKeyJwk,
          servicesToAdd: op.content?.addServices,
          idsOfServicesToRemove: op.content?.removeServices,
          publicKeysToAdd: op.content?.addPublicKeys,
          idsOfPublicKeysToRemove: op.content?.removePublicKeys,
        });
        break;

      case "recover":
        return RawIonSdk.IonRequest.createRecoverRequest({
          didSuffix: await this.getSuffix(),
          signer:
            options.signer ||
            RawIonSdk.LocalSigner.create(op.previous.recovery.privateJwk),
          recoveryPublicKey: op.previous.recovery.publicKeyJwk,
          nextRecoveryPublicKey: op.recovery.publicKeyJwk,
          nextUpdatePublicKey: op.update.publicKeyJwk,
          document: op.content,
        });
        break;

      case "deactivate":
        return RawIonSdk.IonRequest.createDeactivateRequest({
          didSuffix: await this.getSuffix(),
          recoveryPublicKey: op.previous.recovery.publicKeyJwk,
          signer:
            options.signer ||
            RawIonSdk.LocalSigner.create(op.previous.recovery.privateJwk),
        });
        break;

      case "create":
      default:
        return RawIonSdk.IonRequest.createCreateRequest({
          recoveryKey: op.recovery.publicKeyJwk,
          updateKey: op.update.publicKeyJwk,
          document: op.content,
        });
    }
  }
};

module.exports = ION;
