
import './App.css'
import { Routes,Route,BrowserRouter } from 'react-router-dom'
import Landing from './modules/landing/pages/Landing'
import Login from './modules/auth/pages/Login'
import Register from "./modules/auth/pages/Register"

function App() {

  return (

    <BrowserRouter>
      <Routes>
        <Route path='/' element={<Landing />} />
        <Route path='/login' element={<Login />} />
        <Route path="/register" element={<Register />} />

      </Routes>

    </BrowserRouter>
   
  
  )
}

export default App
