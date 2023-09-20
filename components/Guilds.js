import { signIn, signOut, useSession } from "next-auth/client";

export default () => {
  const [session, loading] = useSession();

  return <div className="center">{session.user.name}</div>;
};
