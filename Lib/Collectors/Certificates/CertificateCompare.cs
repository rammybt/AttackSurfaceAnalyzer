// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using System;
using System.Collections.Generic;
using AttackSurfaceAnalyzer.Utils;
using System.Data.SQLite;
using AttackSurfaceAnalyzer.ObjectTypes;
using Serilog;
using Newtonsoft.Json;

namespace AttackSurfaceAnalyzer.Collectors.Certificates
{
    public class CertificateCompare : BaseCompare
    {
        private static readonly string SELECT_INSERTED_SQL = "select row_key,serialized from certificates b where b.run_id = @second_run_id and hash_plus_store not in (select hash_plus_store from certificates a where a.run_id = @first_run_id);";
        private static readonly string SELECT_DELETED_SQL = "select row_key,serialized from certificates a where a.run_id = @first_run_id and hash_plus_store not in (select hash_plus_store from certificates b where b.run_id = @second_run_id);";

        public CertificateCompare()
        {
            Results = new Dictionary<string, object>
            {
                ["certs_add"] = new List<CertificateResult>(),
                ["certs_remove"] = new List<CertificateResult>(),
                ["certs_modify"] = new List<CertificateResult>(),
            };
            _type = RESULT_TYPE.CERTIFICATE;
        }

        public override void Compare(string firstRunId, string secondRunId)
        {
            try
            {
                if (firstRunId == null)
                {
                    throw new ArgumentNullException("firstRunId");
                }
                if (secondRunId == null)
                {
                    throw new ArgumentNullException("secondRunId");
                }
                

                var addObjects = new List<CertificateResult>();
                var cmd = new SQLiteCommand(SELECT_INSERTED_SQL, DatabaseManager.Connection);
                cmd.Parameters.AddWithValue("@first_run_id", firstRunId);
                cmd.Parameters.AddWithValue("@second_run_id", secondRunId);
                using (var reader = cmd.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        var obj = new CertificateResult()
                        {
                            BaseRunId = firstRunId,
                            CompareRunId = secondRunId,
                            CompareRowKey = reader["row_key"].ToString(),
                            Compare = JsonConvert.DeserializeObject<CertificateObject>(Brotli.DecodeString(reader["serialized"] as byte[])),
                            ChangeType = CHANGE_TYPE.CREATED,
                            ResultType = RESULT_TYPE.CERTIFICATE
                        };
                        addObjects.Add(obj);
                        InsertResult(obj);
                    }
                }
                Results["certs_add"] = addObjects;

                Log.Information("{0} {1} {2}",Strings.Get("Found"), addObjects.Count, Strings.Get("Created"));

                var removeObjects = new List<CertificateResult>();
                cmd = new SQLiteCommand(SELECT_DELETED_SQL, DatabaseManager.Connection);
                cmd.Parameters.AddWithValue("@first_run_id", firstRunId);
                cmd.Parameters.AddWithValue("@second_run_id", secondRunId);
                using (var reader = cmd.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        var obj = new CertificateResult()
                        {
                            BaseRunId = firstRunId,
                            CompareRunId = secondRunId,
                            CompareRowKey = reader["row_key"].ToString(),
                            Base = JsonConvert.DeserializeObject<CertificateObject>(Brotli.DecodeString(reader["serialized"] as byte[])),
                            ChangeType = CHANGE_TYPE.DELETED,
                            ResultType = RESULT_TYPE.CERTIFICATE
                        };
                        removeObjects.Add(obj);
                        InsertResult(obj);
                    }
                }
                Results["certs_remove"] = removeObjects;

                Log.Information("{0} {1} {2}", Strings.Get("Found"), removeObjects.Count, Strings.Get("Deleted"));
            }
            catch (Exception e)
            {
                Log.Debug(e.StackTrace);
                Log.Debug(e.Message);
                Telemetry.TrackTrace(Microsoft.ApplicationInsights.DataContracts.SeverityLevel.Error,e);
            }
        }
    }
}