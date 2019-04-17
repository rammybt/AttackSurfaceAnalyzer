// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using AttackSurfaceAnalyzer.ObjectTypes;
using AttackSurfaceAnalyzer.Utils;
using System.Data.SQLite;
using Newtonsoft.Json;
using Serilog;

namespace AttackSurfaceAnalyzer.Collectors.FileSystem
{
    /// <summary>
    /// Collects Filesystem Data from the local file system.
    /// </summary>
    public class FileSystemCollector : BaseCollector
    {
        private readonly HashSet<string> roots;

        private bool INCLUDE_CONTENT_HASH = false;
        private static readonly string SQL_TRUNCATE = "delete from file_system where run_id=@run_id";

        private static readonly string SQL_INSERT = "insert into file_system (run_id, row_key, path, serialized) values (@run_id, @row_key, @path, @serialized)";

        public void Write(FileSystemObject obj)
        {
            SQLiteCommand cmd = new SQLiteCommand(SQL_INSERT, DatabaseManager.Connection);
            cmd.Parameters.AddWithValue("@run_id", runId);
            cmd.Parameters.AddWithValue("@row_key", obj.RowKey);
            cmd.Parameters.AddWithValue("@path", obj.Path);
            cmd.Parameters.AddWithValue("@serialized", Brotli.EncodeString(JsonConvert.SerializeObject(obj)).ToArray());
            try
            {
                cmd.ExecuteNonQuery();
            }
            catch (Exception e)
            {
                Log.Information(e.StackTrace);
                Log.Information(e.Message);
                Log.Information(e.GetType().ToString());
                Telemetry.TrackTrace(Microsoft.ApplicationInsights.DataContracts.SeverityLevel.Error, e);
            }
        }

        public FileSystemCollector(string runId, bool enableHashing = false, string directories = "")
        {
            this.runId = runId;
            this.roots = new HashSet<string>();
            INCLUDE_CONTENT_HASH = enableHashing;
            if (directories.Equals(""))
            {

            }
            else
            {
                foreach (string path in directories.Split(','))
                {
                    AddRoot(path);
                }
            }

        }

        public void Truncate(string runid)
        {
            var cmd = new SQLiteCommand(SQL_TRUNCATE, DatabaseManager.Connection);
            cmd.Parameters.AddWithValue("@run_id", runId);
        }

        public void AddRoot(string root)
        {
            this.roots.Add(root);
        }

        public void ClearRoots()
        {
            this.roots.Clear();
        }

        public override bool CanRunOnPlatform()
        {
            return RuntimeInformation.IsOSPlatform(OSPlatform.Windows) || RuntimeInformation.IsOSPlatform(OSPlatform.Linux) || RuntimeInformation.IsOSPlatform(OSPlatform.OSX);
        }

        public override void Execute()
        {
            if (!CanRunOnPlatform())
            { 
                return;
            }

            Start();
            
            if (this.roots == null || this.roots.Count() == 0)
            {
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    foreach (var driveInfo in DriveInfo.GetDrives())
                    {
                        if (driveInfo.IsReady && driveInfo.DriveType == DriveType.Fixed)
                        {
                            this.roots.Add(driveInfo.Name);
                        }
                    }
                }
                else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
                {
                    this.roots.Add("/");   // @TODO Improve this
                }
                else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
                {
                    this.roots.Add("/"); // @TODO Improve this
                }
            }

            foreach (var root in this.roots)
            {
                Log.Information("{0} root {1}",Strings.Get("Scanning"),root.ToString());
                try
                {
                    var fileInfoEnumerable = DirectoryWalker.WalkDirectory(root);
                    Parallel.ForEach(fileInfoEnumerable,
                                    (fileInfo =>
                    {
                        try
                        {
                            FileSystemObject obj = null;
                            if (fileInfo is DirectoryInfo)
                            {
                                if (!Filter.IsFiltered(Helpers.RuntimeString(), "Scan", "File", "Path", fileInfo.FullName))
                                {
                                    obj = new FileSystemObject()
                                    {
                                        Path = fileInfo.FullName,
                                        Permissions = FileSystemUtils.GetFilePermissions(fileInfo)
                                    };
                                }
                            }
                            else
                            {
                                if (!Filter.IsFiltered(Helpers.RuntimeString(), "Scan", "File", "Path", fileInfo.FullName))
                                {
                                    obj = new FileSystemObject()
                                    {
                                        Path = fileInfo.FullName,
                                        Permissions = FileSystemUtils.GetFilePermissions(fileInfo),
                                        Size = (ulong)(fileInfo as FileInfo).Length
                                    };
                                    if (INCLUDE_CONTENT_HASH)
                                    {
                                        obj.ContentHash = FileSystemUtils.GetFileHash(fileInfo);
                                    }
                                }
                            }
                            if (obj != null)
                            {
                                Write(obj);
                            }
                        }
                        catch (Exception ex)
                        {
                            Log.Warning(ex, "Error processing {0}", fileInfo?.FullName);
                        }
                    }));
                }
                catch (Exception ex)
                {
                    Log.Warning(ex, "Error collecting file system information: {0}", ex.Message);
                }
            }

            Stop();

            //DatabaseManager.Commit();
        }
    }
}