const express = require('express');
const cors = require('cors');
require('dotenv').config();
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const app = express();
const port = process.env.PORT || 5000;

// middleware
app.use(cors())
app.use(express.json())



const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.vylcgzn.mongodb.net/?retryWrites=true&w=majority`;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  }
});

async function run() {
  try {
    // Connect the client to the server	(optional starting in v4.7)
    // await client.connect();
    const userCollection = client.db("bistroDB").collection("user");
    const menuCollection = client.db("bistroDB").collection("menu");
    const reviewCollection = client.db("bistroDB").collection("reviews");
    const cartCollection = client.db("bistroDB").collection("carts");


    // user related apis
    app.post('/users', async(req, res)=>{
      const user = req.body;
      const result = await userCollection.insertOne(user);
      res.json(result);
    })

    app.get('/users', async(req, res)=>{
      const result = await userCollection.find().toArray();
      res.json(result);
    })
    // menu related apis
    app.get('/menu', async(req, res)=>{
      const result = await menuCollection.find().toArray()
      res.json(result)
    })
    // reviews related apis
    app.get('/reviews', async(req, res)=>{
        const result = await reviewCollection.find().toArray();
        res.json(result);
    })

  
    // carts related apis
    app.get('/carts', async(req, res)=>{
      const email = req.query.email;
      if(!email){
        res.json([]);
      }
      const query = { email : email}
      const result = await cartCollection.find(query).toArray()
      res.json(result)
    })
    app.post('/carts', async(req, res)=>{
      const cart = req.body;
      const result = await cartCollection.insertOne(cart);
      res.json(result);
    })

    app.delete('/carts/:id', async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const result = await cartCollection.deleteOne(query);
      res.json(result);
    })
    // Send a ping to confirm a successful connection
    // await client.db("admin").command({ ping: 1 });
    console.log("Pinged your deployment. You successfully connected to MongoDB!");
  } finally {
    // Ensures that the client will close when you finish/error
    // await client.close();
  }
}
run().catch(console.dir);


app.get('/', (req, res) =>{
    res.json("Bistro BOSS SERVER is running")
})

app.listen(port, () =>{
    console.log(`Bistro Boss Server is running on this port ${port}`)
})