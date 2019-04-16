﻿// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using System;
using System.Collections.Generic;
using System.IO;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using AttackSurfaceAnalyzer.Utils;
using System.Data.SQLite;
using AttackSurfaceAnalyzer.ObjectTypes;
using Newtonsoft.Json;
using Serilog;

namespace AttackSurfaceAnalyzer.Collectors.OpenPorts
{
    public class OpenPortCollector : BaseCollector
    {

        private HashSet<string> processedObjects;

        private static readonly string SQL_INSERT = "insert into network_ports (run_id, row_key, family, address, type, port, process_name, serialized) values (@run_id, @row_key, @family, @address, @type, @port, @process_name, @serialized)";
        private static readonly string SQL_TRUNCATE = "delete from network_ports where run_id = @run_id";

        public OpenPortCollector(string runId)
        {
            if (runId == null)
            {
                throw new ArgumentException("runIdentifier may not be null.");
            }
            this.runId = runId;
            this.processedObjects = new HashSet<string>();
        }

        public void Truncate(string runid)
        {
            var cmd = new SQLiteCommand(SQL_TRUNCATE, DatabaseManager.Connection);
            cmd.Parameters.AddWithValue("@run_id", runId);
            cmd.ExecuteNonQuery();
        }

        /**
         * Can this check run on the current platform?
         */
        public override bool CanRunOnPlatform()
        {
            try
            {
                var osRelease = File.ReadAllText("/proc/sys/kernel/osrelease") ?? "";
                osRelease = osRelease.ToLower();
                if (osRelease.Contains("microsoft") || osRelease.Contains("wsl"))
                {
                    Log.Debug("OpenPortCollector cannot run on WSL until https://github.com/Microsoft/WSL/issues/2249 is fixed.");
                    return false;
                }
            }
            catch (Exception)
            { 
                /* OK to ignore, expecting this on non-Linux platforms. */
            };

            return RuntimeInformation.IsOSPlatform(OSPlatform.Windows) || RuntimeInformation.IsOSPlatform(OSPlatform.Linux) || RuntimeInformation.IsOSPlatform(OSPlatform.OSX);
        }

        public void Write(OpenPortObject obj)
        {
            _numCollected++;

            var objStr = obj.ToString();
            if (this.processedObjects.Contains(objStr))
            {
                Log.Debug("Object already exists, ignoring: {0}", objStr);
                return;
            }

            this.processedObjects.Add(objStr);

            var cmd = new SQLiteCommand(SQL_INSERT, DatabaseManager.Connection);
            cmd.Parameters.AddWithValue("@run_id", this.runId);
            cmd.Parameters.AddWithValue("@row_key", obj.RowKey);
            cmd.Parameters.AddWithValue("@family", obj.family);
            cmd.Parameters.AddWithValue("@address", obj.address);
            cmd.Parameters.AddWithValue("@type", obj.type);
            cmd.Parameters.AddWithValue("@port", obj.port);
            cmd.Parameters.AddWithValue("@process_name", obj.processName ?? "");
            cmd.Parameters.AddWithValue("@serialized", JsonConvert.SerializeObject(obj));
            cmd.ExecuteNonQuery();
        }

        public override void Execute()
        {

            Start();
            Log.Debug("Collecting open port information...");
            Truncate(runId);

            if (!this.CanRunOnPlatform())
            {
                return;
            }

            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                ExecuteWindows();
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                ExecuteLinux();
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                ExecuteOsX();
            }
            else
            {
                Log.Warning("OpenPortCollector is not available on {0}", RuntimeInformation.OSDescription);
            }
            Stop();
        }

        /// <summary>
        /// Executes the OpenPortCollector on Windows. Uses the .NET Core
        /// APIs to gather active TCP and UDP listeners and writes them 
        /// to the database.
        /// </summary>
        public void ExecuteWindows()
        {
            Log.Debug("Collecting open port information (Windows implementation)");
            var properties = IPGlobalProperties.GetIPGlobalProperties();

            foreach (var endpoint in properties.GetActiveTcpListeners())
            {
                var obj = new OpenPortObject()
                {
                    family = endpoint.AddressFamily.ToString(),
                    address = endpoint.Address.ToString(),
                    port = endpoint.Port.ToString(),
                    type = "tcp"
                };
                foreach (ProcessPort p in Win32ProcessPorts.ProcessPortMap.FindAll(x => x.PortNumber == endpoint.Port))
                {
                    obj.processName = p.ProcessName;
                }

                Write(obj);
            }

            foreach (var endpoint in properties.GetActiveUdpListeners())
            {
                var obj = new OpenPortObject()
                {
                    family = endpoint.AddressFamily.ToString(),
                    address = endpoint.Address.ToString(),
                    port = endpoint.Port.ToString(),
                    type = "udp"
                };
                foreach (ProcessPort p in Win32ProcessPorts.ProcessPortMap.FindAll(x => x.PortNumber == endpoint.Port))
                {
                    obj.processName = p.ProcessName;
                }

                Write(obj);
            }
        }

        /// <summary>
        /// Executes the OpenPortCollector on Linux. Calls out to the `ss`
        /// command and parses the output, sending the output to the database.
        /// </summary>
        private void ExecuteLinux()
        {
            Log.Debug("ExecuteLinux()");
            var runner = new ExternalCommandRunner();
            var result = runner.RunExternalCommand("ss", "-ln");

            foreach (var _line in result.Split('\n'))
            {
                var line = _line;
                line = line.ToLower();
                if (!line.Contains("listen"))
                {
                    continue;
                }
                var parts = Regex.Split(line, @"\s+");
                if (parts.Length <= 7)
                {
                    continue;       // Not long enough, must be an error
                }
                string address = null;
                string port = null;

                var addressMatches = Regex.Match(parts[4], @"^(.*):(\d+)$");
                if (addressMatches.Success)
                {
                    address = addressMatches.Groups[1].ToString();
                    port = addressMatches.Groups[2].ToString();

                    var obj = new OpenPortObject()
                    {
                        family = parts[0],//@TODO: Determine IPV4 vs IPv6 via looking at the address
                        address = address,
                        port = port,
                        type = parts[0]
                    };
                    Write(obj);
                }
            }
        }

        /// <summary>
        /// Executes the OpenPortCollector on OS X. Calls out to the `lsof`
        /// command and parses the output, sending the output to the database.
        /// The 'ss' command used on Linux isn't available on OS X.
        /// </summary>
        private void ExecuteOsX()
        {
            Log.Debug("ExecuteOsX()");
            var runner = new ExternalCommandRunner();
            var result = runner.RunExternalCommand("sudo", "lsof -Pn -i4 -i6");

            foreach (var _line in result.Split('\n'))
            {
                var line = _line.ToLower();
                if (!line.Contains("listen"))
                {
                    continue; // Skip any lines which aren't open listeners
                }
                var parts = Regex.Split(line, @"\s+");
                if (parts.Length <= 9)
                {
                    continue;       // Not long enough
                }
                string address = null;
                string port = null;

                var addressMatches = Regex.Match(parts[8], @"^(.*):(\d+)$");
                if (addressMatches.Success)
                {
                    address = addressMatches.Groups[1].ToString();
                    port = addressMatches.Groups[2].ToString();

                    var obj = new OpenPortObject()
                    {
                        // Assuming family means IPv6 vs IPv4
                        family = parts[4],
                        address = address,
                        port = port,
                        type = parts[7],
                        processName = parts[0]
                    };
                    Write(obj);
                }
            }
        }
    }
}