import { Db, MongoClient } from 'mongodb'

const uri = process.env.MONGODB_URI
const dbName = process.env.MONGODB_DB || 'tls_phishing_checker'

let cachedClient: MongoClient | null = null
let cachedDb: Db | null = null

export async function getDb() {
  if (!uri) return null

  if (cachedClient && cachedDb) {
    return cachedDb
  }

  const client = new MongoClient(uri)
  await client.connect()

  cachedClient = client
  cachedDb = client.db(dbName)

  return cachedDb
}
