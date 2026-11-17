using System;
using System.Collections.Generic;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Pus.Vault.Common
{
    // DATA TRANSFER OBJECTS (DTOs) FOR JSON PAYLOADS

    public class HelloPayload
    {
        [JsonPropertyName("clientName")]
        public string ClientName { get; set; } = string.Empty;

        [JsonPropertyName("timestamp")]
        public long Timestamp { get; set; }
    }

    public class HelloAckPayload
    {
        [JsonPropertyName("serverVersion")]
        public string ServerVersion { get; set; } = string.Empty;

        [JsonPropertyName("serverNonce")]
        public string ServerNonce { get; set; } = string.Empty;

        [JsonPropertyName("timestamp")]
        public long Timestamp { get; set; }
    }

    public class AuthPayload
    {
        [JsonPropertyName("username")]
        public string Username { get; set; } = string.Empty;

        [JsonPropertyName("password")]
        public string Password { get; set; } = string.Empty;

        [JsonPropertyName("serverNonceEcho")]
        public string ServerNonceEcho { get; set; } = string.Empty;

        [JsonPropertyName("timestamp")]
        public long Timestamp { get; set; }
    }

    public class AuthAckPayload
    {
        [JsonPropertyName("sessionToken")]
        public string SessionToken { get; set; } = string.Empty;

        [JsonPropertyName("hmacSecret")]
        public string HmacSecret { get; set; } = string.Empty;

        [JsonPropertyName("role")]
        public string Role { get; set; } = string.Empty;
    }

    public class DataReqPayload
    {
        [JsonPropertyName("sessionToken")]
        public string SessionToken { get; set; } = string.Empty;

        [JsonPropertyName("action")]
        public string Action { get; set; } = string.Empty;

        [JsonPropertyName("key")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string? Key { get; set; }

        [JsonPropertyName("value")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string? Value { get; set; }

        [JsonPropertyName("timestamp")]
        public long Timestamp { get; set; }

        [JsonPropertyName("hmac")]
        public string Hmac { get; set; } = string.Empty;
    }

    public class DataRespPayload
    {
        [JsonPropertyName("status")]
        public string Status { get; set; } = "OK";

        [JsonPropertyName("action")]
        public string Action { get; set; } = string.Empty;

        [JsonPropertyName("key")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string? Key { get; set; }

        [JsonPropertyName("value")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string? Value { get; set; }

        [JsonPropertyName("keys")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public List<string>? Keys { get; set; }

        [JsonPropertyName("timestamp")]
        public long Timestamp { get; set; }
    }

    public class ErrorPayload
    {
        [JsonPropertyName("errorCode")]
        public int ErrorCode { get; set; }

        [JsonPropertyName("errorName")]
        public string ErrorName { get; set; } = string.Empty;

        [JsonPropertyName("message")]
        public string Message { get; set; } = string.Empty;

        [JsonPropertyName("timestamp")]
        public long Timestamp { get; set; }
    }

    /// <summary>
    /// Helper class for strict UTF-8 JSON serialization and validation.
    /// </summary>
    public static class PvspJsonSerializer
    {
        // Compact JSON serializer options without unnecessary escaping (so '+' in Base64 stays '+')
        private static readonly JsonSerializerOptions SerializerOptions = new()
        {
            WriteIndented = false,
            Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
        };

        // Strict UTF-8 encoding that throws an exception on invalid byte sequences (no BOM)
        private static readonly UTF8Encoding StrictUtf8 = new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

        /// <summary>
        /// Serializes a payload object into compact UTF-8 JSON bytes.
        /// </summary>
        public static byte[] SerializeToUtf8Bytes<T>(T payload)
        {
            string json = JsonSerializer.Serialize(payload, SerializerOptions);
            return StrictUtf8.GetBytes(json);
        }

        /// <summary>
        /// Strictly validates and parses raw UTF-8 bytes into a JSON object, checking for:
        /// 1. Valid UTF-8 encoding and valid JSON syntax -> otherwise returns 104 ERR_INVALID_JSON.
        /// 2. Root must be a JSON Object, no duplicate keys, no unknown keys, no null values -> otherwise 106 ERR_INVALID_PAYLOAD.
        /// </summary>
        public static bool TryParseStrictJsonObject(
            byte[] utf8Bytes,
            HashSet<string> allowedFields,
            HashSet<string> requiredFields,
            out Dictionary<string, JsonElement> parsedFields,
            out int errorCode,
            out string errorMessage)
        {
            parsedFields = new Dictionary<string, JsonElement>(StringComparer.Ordinal);
            errorCode = 0;
            errorMessage = string.Empty;

            // Step 1: Validate strict UTF-8 byte encoding
            string jsonString;
            try
            {
                jsonString = StrictUtf8.GetString(utf8Bytes);
            }
            catch (DecoderFallbackException)
            {
                errorCode = PvspErrorCodes.InvalidJson;
                errorMessage = "Payload is not valid UTF-8 text.";
                return false;
            }

            // Step 2: Parse JSON document
            JsonDocument doc;
            try
            {
                doc = JsonDocument.Parse(jsonString);
            }
            catch (JsonException)
            {
                errorCode = PvspErrorCodes.InvalidJson;
                errorMessage = "Malformed JSON document.";
                return false;
            }

            using (doc)
            {
                // Root element must be a JSON object {...}, not an array [...] or primitive
                if (doc.RootElement.ValueKind != JsonValueKind.Object)
                {
                    errorCode = PvspErrorCodes.InvalidPayload;
                    errorMessage = "JSON root must be an object.";
                    return false;
                }

                // Step 3: Iterate through all properties to detect duplicates, unknown fields, or nulls
                foreach (JsonProperty prop in doc.RootElement.EnumerateObject())
                {
                    if (!allowedFields.Contains(prop.Name))
                    {
                        errorCode = PvspErrorCodes.InvalidPayload;
                        errorMessage = $"Unknown JSON field: '{prop.Name}'.";
                        return false;
                    }

                    if (parsedFields.ContainsKey(prop.Name))
                    {
                        errorCode = PvspErrorCodes.InvalidPayload;
                        errorMessage = $"Duplicate JSON field: '{prop.Name}'.";
                        return false;
                    }

                    if (prop.Value.ValueKind == JsonValueKind.Null)
                    {
                        errorCode = PvspErrorCodes.InvalidPayload;
                        errorMessage = $"Field '{prop.Name}' cannot be null.";
                        return false;
                    }

                    // Clone the element so it remains valid after JsonDocument is disposed
                    parsedFields[prop.Name] = prop.Value.Clone();
                }

                // Step 4: Ensure all required fields are present
                foreach (string req in requiredFields)
                {
                    if (!parsedFields.ContainsKey(req))
                    {
                        errorCode = PvspErrorCodes.InvalidPayload;
                        errorMessage = $"Missing required JSON field: '{req}'.";
                        return false;
                    }
                }
            }

            return true;
        }

        /// <summary>
        /// Helper to extract a non-empty string within a UTF-8 byte limit.
        /// </summary>
        public static bool TryGetStringField(
            Dictionary<string, JsonElement> fields,
            string fieldName,
            int maxUtf8Bytes,
            bool allowEmpty,
            out string value,
            out string error)
        {
            value = string.Empty;
            error = string.Empty;

            if (!fields.TryGetValue(fieldName, out JsonElement elem) || elem.ValueKind != JsonValueKind.String)
            {
                error = $"Field '{fieldName}' must be a string.";
                return false;
            }

            value = elem.GetString() ?? string.Empty;
            if (!allowEmpty && value.Length == 0)
            {
                error = $"Field '{fieldName}' cannot be empty.";
                return false;
            }

            int byteCount = StrictUtf8.GetByteCount(value);
            if (byteCount > maxUtf8Bytes)
            {
                error = $"Field '{fieldName}' exceeds maximum length of {maxUtf8Bytes} UTF-8 bytes.";
                return false;
            }

            return true;
        }

        /// <summary>
        /// Helper to extract a signed 64-bit integer (int64) field such as timestamp.
        /// </summary>
        public static bool TryGetInt64Field(
            Dictionary<string, JsonElement> fields,
            string fieldName,
            out long value,
            out string error)
        {
            value = 0;
            error = string.Empty;

            if (!fields.TryGetValue(fieldName, out JsonElement elem) ||
                elem.ValueKind != JsonValueKind.Number ||
                !elem.TryGetInt64(out value))
            {
                error = $"Field '{fieldName}' must be a valid 64-bit integer.";
                return false;
            }

            return true;
        }

        /// <summary>
        /// Validates that a secret key contains only allowed ASCII characters: alphanumeric, '_', '-', '.'.
        /// </summary>
        public static bool IsValidSecretKeyFormat(string key)
        {
            if (string.IsNullOrEmpty(key) || Encoding.UTF8.GetByteCount(key) > PvspConstants.MaxKeyBytes)
                return false;

            foreach (char c in key)
            {
                bool isAlphaNum = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9');
                bool isSpecial = c == '_' || c == '-' || c == '.';
                if (!isAlphaNum && !isSpecial)
                    return false;
            }

            return true;
        }
    }
}