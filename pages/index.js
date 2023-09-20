import { signIn, signOut, useSession } from "next-auth/client";
import Guilds from "../components/Guilds";

export default function Page() {
  const [session, loading] = useSession();

  return (
    <>
      {!session && (
        <>
          <button onClick={signIn}>Sign in</button>
        </>
      )}
      {session && (
        <>
          Signed in as {session.user.email} <br />
          <button onClick={signOut}>Sign out</button>
          <Guilds></Guilds>
        </>
      )}
    </>
  );
}
