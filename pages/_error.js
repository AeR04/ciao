// https://http.cat/101.jpg
import "../styles/_error.module.css";

function Error({ statusCode }) {
  return (
    <img
      src={`https://http.cat/${statusCode}`}
      alt={
        statusCode
          ? `An error ${statusCode} occurred`
          : "An error occurred on client"
      }
      className="err"
    />
  );
}

Error.getInitialProps = ({ res, err }) => {
  const statusCode = res ? res.statusCode : err ? err.statusCode : 404;
  return { statusCode };
};

export default Error;
