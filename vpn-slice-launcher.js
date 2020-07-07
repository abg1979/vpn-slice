//
// vpnc-script-win.js
//
// Sets up the Network interface and the routes
// needed by vpnc.
//

var ws = WScript.CreateObject("WScript.Shell");
var comspec = ws.ExpandEnvironmentStrings("%comspec%");

function echo(msg)
{
	WScript.echo(msg);
}

function exec(cmd)
{
	echo("<<-- [EXEC] " + cmd);
	var oExec = ws.Exec(comspec + " /C \"" + cmd + "\" 2>&1");
	oExec.StdIn.Close();
	var exitCode = oExec.ExitCode;
	echo("-->> (exitCode: " + exitCode + ")");
	return exitCode;
}

var command = "vpnc.cmd";

for (var i = 0; i < WScript.Arguments.length; i++) {
	command += " ";
	command += WScript.Arguments[i];
}

var vpnArguments = ['10.0.0.0/8', '--dump'];
//var vpnArguments = [];
for (var i = 0; i < vpnArguments.length; i++) {
	command += " ";
	command += vpnArguments[i];
}


WScript.Quit(exec(command));
