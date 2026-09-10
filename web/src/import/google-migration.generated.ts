import * as $protobuf from "protobufjs/minimal";

// Static decoder for the Google Authenticator MigrationPayload protobuf schema.
// The schema is represented in code so importing credentials never requires runtime schema loading.
export interface GoogleMigrationOtpParameters {
  secret: Uint8Array;
  name: string;
  issuer: string;
  algorithm: number;
  digits: number;
  type: number;
}

export interface GoogleMigrationPayload {
  otpParameters: GoogleMigrationOtpParameters[];
  version: number;
  batchSize: number;
  batchIndex: number;
  batchId: number;
}

export function decodeGoogleMigrationPayload(input: Uint8Array): GoogleMigrationPayload {
  const reader = $protobuf.Reader.create(input);
  const payload: GoogleMigrationPayload = {
    otpParameters: [],
    version: 0,
    batchSize: 0,
    batchIndex: 0,
    batchId: 0,
  };

  while (reader.pos < reader.len) {
    const tag = reader.uint32();
    switch (tag >>> 3) {
      case 1:
        payload.otpParameters.push(decodeOtpParameters(reader, reader.uint32()));
        break;
      case 2:
        payload.version = reader.int32();
        break;
      case 3:
        payload.batchSize = reader.int32();
        break;
      case 4:
        payload.batchIndex = reader.int32();
        break;
      case 5:
        payload.batchId = reader.int32();
        break;
      default:
        reader.skipType(tag & 7);
        break;
    }
  }

  return payload;
}

function decodeOtpParameters(reader: $protobuf.Reader, length: number): GoogleMigrationOtpParameters {
  const end = reader.pos + length;
  const parameters: GoogleMigrationOtpParameters = {
    secret: new Uint8Array(),
    name: "",
    issuer: "",
    algorithm: 0,
    digits: 0,
    type: 0,
  };

  while (reader.pos < end) {
    const tag = reader.uint32();
    switch (tag >>> 3) {
      case 1:
        parameters.secret = reader.bytes();
        break;
      case 2:
        parameters.name = reader.string();
        break;
      case 3:
        parameters.issuer = reader.string();
        break;
      case 4:
        parameters.algorithm = reader.int32();
        break;
      case 5:
        parameters.digits = reader.int32();
        break;
      case 6:
        parameters.type = reader.int32();
        break;
      case 7:
        reader.uint64();
        break;
      default:
        reader.skipType(tag & 7);
        break;
    }
  }

  return parameters;
}
