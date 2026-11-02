> [!TIP]
> This _README.md_ file is copied from https://my-thos.github.io/the-end-of-the-launcher/ with minor revisions to improve clarity. Fortunately, the original text was very clear and easy to follow. I like that!

# "The End of the Launcher"

https://github.com/user-attachments/assets/16125423-9098-428b-8fd5-95c7b91b565c

We can use Roblox's trust in the server to achieve server-to-client RCE using malicious bytecode on clients versioned late 2014 and above.

## The history of Bytecode on Roblox

Bytecode was used by Roblox developers back around 2008-2011 to "obfuscate" their game as there was at the time, no Lua 5.1 bytecode decompilers. A example of this is Armored Patrol, where most of the serverscripts run bytecode via loadstring.

This obfuscation tactic would be killed on August 3, 2012, with Roblox citing security reasons. An excerpt from their blog post [Bye Bye Bytecode](https://web.archive.org/web/20220116224345/https://blog.roblox.com/2012/08/bye-bye-bytecode/) explains more

> Unfortunately, the version of Lua that ROBLOX uses (5.1) has several virtual machine-level defects that can be exploited with the use of bytecode. ROBLOX user Necrobumpist found this article that discusses some of them. The nastiest one allows you to hijack the stack of another function running in another security context. In short, if you know what you are doing, you can craft a privilege elevation attack using bytecode. The Lua community at one point was working on a bytecode validator for loadstring to prevent these sorts of shenanigans, but it was eventually deemed infeasible and it is now the responsibility of developers embedding Lua to filter out bad bytecode themselves (presumably by disabling it).

This flaw has been known for a while now. In 2023, GitHub user @stan2474 blew the whistle on it leading to it's patch in Novetus, and other launchers. Hip hip, hooray! A critical vulnerability has now been patched, and the only way to run bytecode was via loadstring. Disabling that has killed every way to execute bytecode, so there's no way this issue should come back, right?

## And in 2014...

It is now late 2014 and exploiters are on the platform stealing exact LocalScript source code. Since 2012, the company has had a way to fix this, an FFlag with the name "LuaEnableBytecode". Instead of sending the client the source code of LocalScripts, this would make it so that they are compiled on the server and sent to the client.

But wouldn't this be introducing a critical vulnerability again? No. Roblox is the one that compiles the source code to bytecode, and sends it to your client to run that bytecode. Roblox won't randomly send you malicious bytecode and it makes no sense for the client to have the source code to LocalScripts anyway.

So, they go with it, and with this, they also remove the Lua compiler from the client. The client can now only run bytecode, and bytecode sent from the server to the client. In an attempt to confuse cheaters, they also send the bytecode to the client in a little "container" (RSB1, but I won't be getting to this here) that contains the bytecode compressed and encoded. They also remove the FFlag.

This works perfectly. There are no issues. Roblox will always host the server, right?

## The "Vulnerability"

With launchers, random people can host or join servers. Roblox never intended this, as they had the mentality that every person hosting would be themselves.

So what is the problem? Some random guy can make my client run bytecode when I join his server? So what?

[The client should never run untrusted bytecode.](https://gist.github.com/ntherning/5c808312f3805d37f98fcc5a954875ae) This was one of the concerns Roblox had in 2012, as it is basically a free ACE by doing so. So, let's get to the good part.

## The Patch

**A patch is ready for versions 2014L thru 2016L (tested on Kanvas clients). You can download it [here](https://github.com/Windows81/Roblox-LuaPatch/archive/refs/heads/main.zip).**

The `./tools/index.html` contains an auto address grabber to help you. As of 2026-10-31, Kanvas released their own patch (i.e., the TB3 Bytecode clients patch \[sic\]).

This patch works by making it so instead of sending bytecode to the client, the server sends the source code to the client, and the client compiles it. If you try to join an unpatched server on a patched client, no LocalScripts will run on your client. Although, the patch is designed in a way where unpatched clients can still run LocalScripts from the patched server.

Patching this gets exponentially harder over the years due to stuff like the Dynamic Bot Challenge (that runs bytecode on your client from the server to confirm you aren't a bot), random intentional messups of the Lua VM to stop exploiters, Luau, etc.

> [!NOTE] 
> This doesn't affect ORRH, or Novetus, although Kanvas was affected for Roblox versions after 2014M (prior to 2026-10-31). This also doesn't just affect Kanvas, this affects anything that allows you to host/join on any client version after 2014M (2014L is affected). Yes, any local_rcc server or variation of local_rcc. Yes, if it were even possible to host latest Roblox, it would be affected. As said before, **You should only be playing servers hosted by people you trust.**

### (No) Proof of Concept

It is not in the original authors' interest to release a PoC that can be weaponized to compromise people's systems.

However, if an exploit becomes knwon to VisualPlugin, he'll post it straight away on this GitHub page.
https://github.com/user-attachments/assets/23ee2141-1f7e-42b5-9de2-680c313ae20f

## Disclosure Disclaimer

The original author(s) planned to release this writeup on 2026-10-31, after his team had sent a patch to the Kanvas developers on 2026-10-30. After announcing the risk to people, someone had decided to publicly release a vibecoded exploit exploiting the vulnerability. Great! This is the reason why this writeup's release was released early.
