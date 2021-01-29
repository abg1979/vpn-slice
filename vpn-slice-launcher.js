//
// vpnc-script-win.js
//
// Sets up the Network interface and the routes
// needed by vpnc.
//

var ws = WScript.CreateObject("WScript.Shell");
var comspec = ws.ExpandEnvironmentStrings("%comspec%");

function paddy(num, padlen, padchar) {
    var pad_char = typeof padchar !== 'undefined' ? padchar : '0';
    var pad = new Array(1 + padlen).join(pad_char);
    return (pad + num).slice(-pad.length);
}

function echo(msg) {
    var now = new Date();
    var formattedTime = now.getFullYear() + "-" + paddy(now.getMonth() + 1, 2) + "-" + paddy(now.getDate(), 2) + " " + paddy(now.getHours(), 2) + ":" + paddy(now.getMinutes(), 2) + ":" + paddy(now.getSeconds(), 2)
    WScript.echo("[" + formattedTime + "] " + msg);
}

function exec(cmd) {
    echo("<<-- [EXEC] " + cmd);
    var oExec = ws.Exec(comspec + " /C \"" + cmd + "\" 2>&1");
    oExec.StdIn.Close();

    var s = oExec.StdOut.ReadAll();
    echo("STDOUT -->>")
    echo(s);

    s = oExec.StdErr.ReadAll();
    echo("STDERR -->>")
    echo(s);

    var exitCode = oExec.ExitCode;
    echo("-->> (exitCode: " + exitCode + ")");

    return exitCode;
}

var command = "vpnc.cmd";
for (var i = 0; i < WScript.Arguments.length; i++) {
    command += " ";
    command += WScript.Arguments[i];
}

WScript.Quit(exec(command));
