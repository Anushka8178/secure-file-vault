import { Link } from 'react-router-dom';
import { useAuth } from '../hooks/useAuth.jsx';

export default function Navbar() {
  const { user, logout } = useAuth();

  // Only show the navbar if the user is authenticated
  if (!user) return null;

  return (
    <nav style={styles.nav}>
      <div style={styles.container}>
        <div style={styles.brand}>Secure Vault</div>
        <div style={styles.links}>
          <Link to="/dashboard" style={styles.link}>Dashboard</Link>
          <Link to="/upload" style={styles.link}>Upload</Link>
          <Link to="/links" style={styles.link}>Secure Links</Link>
          {user.role === 'admin' && (
            <Link to="/admin" style={styles.link}>Admin</Link>
          )}
          <button onClick={logout} style={styles.logoutBtn}>Logout</button>
        </div>
      </div>
    </nav>
  );
}

const styles = {
  nav: {
    backgroundColor: '#1a1a2e',
    padding: '1rem',
    color: '#fff',
    fontFamily: 'system-ui, sans-serif'
  },
  container: {
    maxWidth: 1000,
    margin: '0 auto',
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center'
  },
  brand: {
    fontSize: '1.2rem',
    fontWeight: 'bold',
  },
  links: {
    display: 'flex',
    gap: '1.5rem',
    alignItems: 'center'
  },
  link: {
    color: '#fff',
    textDecoration: 'none',
    fontSize: '0.95rem'
  },
  logoutBtn: {
    backgroundColor: '#c0392b',
    color: '#fff',
    border: 'none',
    padding: '0.4rem 0.8rem',
    borderRadius: '4px',
    cursor: 'pointer',
    fontWeight: 'bold',
    fontSize: '0.9rem'
  }
};
